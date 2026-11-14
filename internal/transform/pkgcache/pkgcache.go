// Package pkgcache implements a read-through cache for package files (npm
// tarballs, NuGet .nupkg files and the like), stored in S3, an S3-compatible
// service, or a local directory.
//
// On a request for a cacheable file, the transform looks the file up in the
// store. A hit is answered from the store (ActionStub, audited as "stub") and
// the registry is never contacted. A miss goes to the registry as normal, and
// the response is copied into the store while it streams to the client.
//
// It fails open: any store error, timeout or surprise means the request goes
// to the registry exactly as it would without the cache. A broken cache makes
// installs slower, never failing.
//
// Only immutable files are cached: HTTPS GET requests on port 443 with no
// Cookie or Range header, no query string, no encoded characters in the
// path, and a path no transform rewrote,
// whose host and path match one of the configured caches. Version lists and
// other metadata change all the time and must not match the configured
// paths.
//
// Credentials don't stop a file being cached: a request with an
// Authorization header, or one a transform injected a credential into, is
// cached like any other, and a hit is served without checking credentials.
// iron-proxy rules can't be scoped to a client, so any client of the proxy
// can already get an injected credential applied; but a file fetched with a
// client's own key is then served to clients without it. Only configure
// caches for registries where that's acceptable.
//
// The registries' hosts must be decrypted (tls.intercept) for the transform
// to see their requests. List this transform last in transforms:, so it sees
// each request after every other transform (and so after any path rewrite).
//
// Storage is either S3 (bucket, with optional region, endpoint and
// use_path_style for S3-compatible services) or a local directory
// (directory). Exactly one of bucket and directory is set.
//
// Example:
//
//	transforms:
//	  - name: pkgcache
//	    config:
//	      bucket: example-pkgcache
//	      region: af-south-1
//	      caches:
//	        - prefix: npm
//	          rules:
//	            - host: registry.npmjs.org
//	              paths: ["/*/-/*.tgz", "/@*/*/-/*.tgz"]
//	        - prefix: nuget
//	          rules:
//	            - host: api.nuget.org
//	              paths: ["/v3-flatcontainer/*/*/*.nupkg"]
package pkgcache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("pkgcache", factory)
}

// Defaults for the optional settings.
const (
	defaultLookupTimeout        = 2 * time.Second
	defaultHitReadTimeout       = 10 * time.Minute
	defaultUploadTimeout        = 10 * time.Minute
	defaultUploadIdleTimeout    = 60 * time.Second
	defaultMaxObjectBytes       = 1 << 30 // 1 GiB
	defaultMaxQueuedBytes       = 8 << 20 // 8 MiB per upload
	defaultMaxConcurrentUploads = 32
	maxKeyLength                = 1024 // S3's limit
)

type cacheConfig struct {
	// Prefix starts every key this cache stores, e.g. "npm".
	Prefix string                 `yaml:"prefix"`
	Rules  []hostmatch.RuleConfig `yaml:"rules"`
}

type config struct {
	// S3 storage. Endpoint and UsePathStyle are for S3-compatible services
	// (MinIO, Cloudflare R2, ...); leave them out for AWS.
	Bucket       string `yaml:"bucket"`
	Region       string `yaml:"region"`
	Endpoint     string `yaml:"endpoint"`
	UsePathStyle bool   `yaml:"use_path_style"`

	// Local directory storage, instead of a bucket.
	Directory string `yaml:"directory"`

	// LookupTimeout bounds the store lookup before a request; past it, the
	// request goes to the registry.
	LookupTimeout time.Duration `yaml:"lookup_timeout"`
	// HitReadTimeout bounds streaming one hit to the client.
	HitReadTimeout time.Duration `yaml:"hit_read_timeout"`
	// UploadTimeout bounds one upload after a miss.
	UploadTimeout time.Duration `yaml:"upload_timeout"`
	// UploadIdleTimeout abandons an upload when the client stops reading.
	UploadIdleTimeout time.Duration `yaml:"upload_idle_timeout"`
	// MaxObjectBytes: larger responses aren't stored.
	MaxObjectBytes int64 `yaml:"max_object_bytes"`
	// MaxQueuedBytes: how far one upload may fall behind its client before
	// it's abandoned. Bounds memory per upload.
	MaxQueuedBytes int64 `yaml:"max_queued_bytes"`
	// MaxConcurrentUploads: misses beyond this aren't stored. With
	// MaxQueuedBytes, bounds the transform's memory.
	MaxConcurrentUploads int `yaml:"max_concurrent_uploads"`

	Caches []cacheConfig `yaml:"caches"`
}

type cache struct {
	prefix string
	rules  []hostmatch.Rule
}

// PkgCache is the transform.
type PkgCache struct {
	store   store
	caches  []cache
	cfg     config
	uploads chan struct{} // one slot per running upload
	logger  *slog.Logger
}

func factory(node yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c config
	if err := node.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing pkgcache config: %w", err)
	}
	st, err := newStore(c)
	if err != nil {
		return nil, err
	}
	return newFromConfig(c, st, logger)
}

// newStore builds the configured storage: a bucket or a directory, exactly
// one of them.
func newStore(c config) (store, error) {
	switch {
	case c.Bucket != "" && c.Directory != "":
		return nil, fmt.Errorf("pkgcache: set bucket or directory, not both")
	case c.Directory != "":
		if c.Region != "" || c.Endpoint != "" || c.UsePathStyle {
			return nil, fmt.Errorf("pkgcache: region, endpoint and use_path_style only apply to a bucket")
		}
		return newDirStore(c.Directory)
	case c.Bucket != "":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return newS3Store(ctx, s3Settings{
			Bucket:       c.Bucket,
			Region:       c.Region,
			Endpoint:     c.Endpoint,
			UsePathStyle: c.UsePathStyle,
		})
	default:
		return nil, fmt.Errorf("pkgcache: set bucket (S3) or directory (local disk)")
	}
}

func newFromConfig(c config, st store, logger *slog.Logger) (*PkgCache, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if len(c.Caches) == 0 {
		return nil, fmt.Errorf("pkgcache: at least one cache is required")
	}
	setDefault(&c.LookupTimeout, defaultLookupTimeout)
	setDefault(&c.HitReadTimeout, defaultHitReadTimeout)
	setDefault(&c.UploadTimeout, defaultUploadTimeout)
	setDefault(&c.UploadIdleTimeout, defaultUploadIdleTimeout)
	if c.MaxObjectBytes <= 0 {
		c.MaxObjectBytes = defaultMaxObjectBytes
	}
	if c.MaxQueuedBytes <= 0 {
		c.MaxQueuedBytes = defaultMaxQueuedBytes
	}
	if c.MaxConcurrentUploads <= 0 {
		c.MaxConcurrentUploads = defaultMaxConcurrentUploads
	}

	caches := make([]cache, 0, len(c.Caches))
	seen := map[string]bool{}
	for i, cc := range c.Caches {
		prefix := strings.Trim(cc.Prefix, "/")
		if prefix == "" {
			return nil, fmt.Errorf("pkgcache: caches[%d]: prefix is required", i)
		}
		if seen[prefix] {
			return nil, fmt.Errorf("pkgcache: caches[%d]: prefix %q is used twice", i, prefix)
		}
		seen[prefix] = true
		if len(cc.Rules) == 0 {
			return nil, fmt.Errorf("pkgcache: caches[%d] (%s): at least one rule is required", i, prefix)
		}
		for j, rc := range cc.Rules {
			if len(rc.Paths) == 0 {
				// Without paths, version lists would be cached too, and
				// they change all the time.
				return nil, fmt.Errorf("pkgcache: caches[%d] (%s) rules[%d]: paths are required, matching only immutable package files", i, prefix, j)
			}
		}
		// Not matching only means "not cached", so require_tls is safe here.
		rules, err := hostmatch.CompileRulesAllowRequireTLS(cc.Rules, fmt.Sprintf("pkgcache.caches[%d]", i))
		if err != nil {
			return nil, err
		}
		caches = append(caches, cache{prefix: prefix, rules: rules})
	}

	return &PkgCache{
		store:   st,
		caches:  caches,
		cfg:     c,
		uploads: make(chan struct{}, c.MaxConcurrentUploads),
		logger:  logger,
	}, nil
}

func setDefault(d *time.Duration, def time.Duration) {
	if *d <= 0 {
		*d = def
	}
}

func (p *PkgCache) Name() string { return "pkgcache" }

// cacheKey returns the store key for req, or "" and the reason it isn't
// cacheable. The key is <prefix>/<host><path>, e.g.
// npm/registry.npmjs.org/react/-/react-18.3.1.tgz.
func (p *PkgCache) cacheKey(req *http.Request) (string, string) {
	if req.Method != http.MethodGet {
		return "", "not a GET"
	}
	// Only the registry itself, over verified TLS, may fill the cache: a
	// plain-HTTP response or another port on the same host would otherwise
	// share the HTTPS keys and be served as if the registry had sent it.
	if req.TLS == nil {
		return "", "not HTTPS"
	}
	if !onDefaultHTTPSPort(req.Host) {
		return "", "not port 443"
	}
	// Session state, not a package credential; registries don't use it.
	if req.Header.Get("Cookie") != "" {
		return "", "has a cookie"
	}
	if req.Header.Get("Range") != "" {
		return "", "range request"
	}
	if req.URL.RawQuery != "" {
		return "", "has a query string"
	}
	// A transform rewrote the path (e.g. secrets swapping a token into the
	// URL). The path may now hold a real credential, which must never become
	// a store key or a log line, and the key would change every time the
	// token rotates anyway.
	if pathRewritten(req) {
		return "", "path rewritten by a transform"
	}
	// Encoded characters (e.g. %2F) are forwarded encoded, so /a%2Fb and
	// /a/b are different files upstream but would share a decoded key.
	// Package file URLs (npm tarballs, NuGet .nupkg) never have them.
	if req.URL.RawPath != "" {
		return "", "encoded characters in the path"
	}
	for _, c := range p.caches {
		if !hostmatch.MatchAnyRule(c.rules, req) {
			continue
		}
		reqPath := req.URL.Path
		if !strings.HasPrefix(reqPath, "/") || path.Clean(reqPath) != reqPath {
			return "", "unusual path"
		}
		host := strings.ToLower(hostmatch.StripPort(req.Host))
		key := c.prefix + "/" + host + reqPath
		if len(key) > maxKeyLength {
			return "", "key too long"
		}
		return key, ""
	}
	return "", "no cache matches"
}

// onDefaultHTTPSPort reports whether host (a Host header) names port 443,
// explicitly or by leaving the port out.
func onDefaultHTTPSPort(host string) bool {
	_, port, err := net.SplitHostPort(host)
	if err != nil {
		return true // no port in the Host header: the default
	}
	return port == "443"
}

// pathRewritten reports whether the request's path differs from the one the
// client sent. RequestURI is the client's request line and never changes;
// req.URL is what transforms edit. An unreadable or missing RequestURI
// counts as rewritten, so the request isn't cached.
func pathRewritten(req *http.Request) bool {
	if req.RequestURI == "" {
		return true
	}
	original, err := url.ParseRequestURI(req.RequestURI)
	if err != nil {
		return true
	}
	return original.EscapedPath() != req.URL.EscapedPath()
}

// TransformRequest answers a cacheable request from the store when it can.
func (p *PkgCache) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	cont := &transform.TransformResult{Action: transform.ActionContinue}

	key, _ := p.cacheKey(req)
	if key == "" {
		return cont, nil // not ours: no annotation, to keep the audit quiet
	}

	obj, err := p.lookup(ctx, key)
	if errors.Is(err, errNotFound) {
		tctx.Annotate("pkgcache", "miss")
		return cont, nil
	}
	if err != nil {
		p.logger.Warn("pkgcache: lookup failed, going to the registry",
			slog.String("key", key), slog.String("error", err.Error()))
		tctx.Annotate("pkgcache", "lookup_error")
		return cont, nil
	}

	tctx.Annotate("pkgcache", "hit")
	header := http.Header{}
	contentType := obj.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	header.Set("Content-Type", contentType)
	if obj.Size >= 0 {
		header.Set("Content-Length", strconv.FormatInt(obj.Size, 10))
	}
	header.Set("X-Iron-Pkgcache", "hit")
	return &transform.TransformResult{
		Action: transform.ActionStub,
		Response: &http.Response{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        header,
			Body:          obj.Body,
			ContentLength: obj.Size,
			Request:       req,
		},
	}, nil
}

// lookup gets key from the store. LookupTimeout bounds the wait for the
// store to answer; HitReadTimeout bounds streaming the whole object.
//
// The proxy never calls Close on a stubbed response's body. So the returned
// body closes itself at the end of the stream, and also as soon as the
// request's context ends: Go cancels it when the proxy's handler returns,
// whether the copy finished or the client went away. That frees the S3
// connection or the open file straight away, not at HitReadTimeout.
func (p *PkgCache) lookup(requestCtx context.Context, key string) (*object, error) {
	ctx, cancel := context.WithTimeout(requestCtx, p.cfg.HitReadTimeout)
	lookupTimer := time.AfterFunc(p.cfg.LookupTimeout, cancel)
	obj, err := p.store.Get(ctx, key)
	timedOut := !lookupTimer.Stop()
	if err != nil {
		cancel()
		if timedOut {
			return nil, fmt.Errorf("pkgcache: lookup took longer than %s: %w", p.cfg.LookupTimeout, err)
		}
		return nil, err
	}
	if timedOut {
		// The store answered just as the timer fired; the context is gone,
		// so the body can't be read. Treat it as a fault.
		obj.Body.Close()
		cancel()
		return nil, fmt.Errorf("pkgcache: lookup took longer than %s", p.cfg.LookupTimeout)
	}
	body := &selfClosingBody{body: obj.Body, cancel: cancel}
	context.AfterFunc(ctx, func() { body.Close() })
	obj.Body = body
	return obj, nil
}

// TransformResponse copies a cacheable miss into the store while it streams
// to the client. It never changes what the client receives.
func (p *PkgCache) TransformResponse(_ context.Context, tctx *transform.TransformContext, req *http.Request, resp *http.Response) (*transform.TransformResult, error) {
	cont := &transform.TransformResult{Action: transform.ActionContinue}

	key, _ := p.cacheKey(req)
	if key == "" {
		return cont, nil
	}
	if reason := p.storeSkipReason(resp); reason != "" {
		tctx.Annotate("pkgcache_store", "skipped: "+reason)
		return cont, nil
	}
	buffered := transform.RequireBufferedBody(resp.Body)
	if buffered.Len() >= 0 {
		// An earlier transform read the whole body into memory. Rare for
		// registries; not worth a second code path.
		tctx.Annotate("pkgcache_store", "skipped: body already buffered")
		return cont, nil
	}

	select {
	case p.uploads <- struct{}{}:
	default:
		tctx.Annotate("pkgcache_store", "skipped: too many uploads running")
		return cont, nil
	}
	release := func() { <-p.uploads }

	settings := uploadSettings{
		maxQueuedBytes: p.cfg.MaxQueuedBytes,
		idleTimeout:    p.cfg.UploadIdleTimeout,
		uploadTimeout:  p.cfg.UploadTimeout,
	}
	// StreamingReader hands over the registry's stream unread. The proxy
	// closes the registry's response itself when the request ends.
	src := io.NopCloser(buffered.StreamingReader())
	body := startUpload(src, key, resp.ContentLength, resp.Header.Get("Content-Type"), p.store, settings, p.logger, release)
	// The pipeline needs a BufferedBody; it buffers only if a later
	// transform reads it, which is why this transform should be listed last.
	resp.Body = transform.NewBufferedBody(body, 0)
	tctx.Annotate("pkgcache_store", "started")
	return cont, nil
}

// storeSkipReason says why resp mustn't be stored, or "" when it may be.
func (p *PkgCache) storeSkipReason(resp *http.Response) string {
	switch {
	case resp.StatusCode != http.StatusOK:
		return "status " + strconv.Itoa(resp.StatusCode)
	case resp.Header.Get("Content-Encoding") != "":
		return "content-encoding " + resp.Header.Get("Content-Encoding")
	case resp.ContentLength < 0:
		return "no Content-Length"
	case resp.ContentLength == 0:
		return "empty body"
	case resp.ContentLength > p.cfg.MaxObjectBytes:
		return "larger than max_object_bytes"
	case strings.Contains(strings.ToLower(resp.Header.Get("Cache-Control")), "private"),
		strings.Contains(strings.ToLower(resp.Header.Get("Cache-Control")), "no-store"):
		return "Cache-Control " + resp.Header.Get("Cache-Control")
	case resp.Header.Get("Set-Cookie") != "":
		return "sets a cookie"
	}
	return ""
}

// selfClosingBody closes the store's body (and cancels its context) at the
// end of the stream, on a read error, or when the request ends, since
// nothing else will. Close can run on another goroutine (context.AfterFunc)
// while a Read is in progress; closing a file or an HTTP body is safe then,
// and the Read just returns an error.
type selfClosingBody struct {
	body      io.ReadCloser
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeErr  error
}

func (s *selfClosingBody) Read(p []byte) (int, error) {
	n, err := s.body.Read(p)
	if err != nil {
		s.Close()
	}
	return n, err
}

func (s *selfClosingBody) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = s.body.Close()
		s.cancel()
	})
	return s.closeErr
}
