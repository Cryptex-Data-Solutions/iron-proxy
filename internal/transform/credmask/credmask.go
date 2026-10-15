// Package credmask implements a transform that keeps durable credentials off
// the client by masking them at birth and swapping them back on the way out.
//
// It is the native Go port of the Cryptex mitmproxy addons
// (github_tokenize.py, oauth_refresh_tokenize.py, vault.py in
// cryptex-dev-sandbox). Two credential families are handled:
//
// GitHub OAuth tokens (gho_/ghu_/ghs_/ghr_/ghp_):
//
//  1. Issuance (response). `gh auth login` polls
//     POST github.com/login/oauth/access_token. When the response carries a
//     real token, the real value goes into the store and the client gets a
//     same-shape mask instead.
//  2. Consumption (request headers only). Later requests carry the mask in
//     Authorization (`token <mask>`, `Bearer <mask>`, or Basic auth with the
//     mask as the password, as git-over-HTTPS does). The mask is swapped for
//     the real token before the request goes upstream. Only headers are
//     touched, so large request bodies (a big `git push`) still stream.
//  3. Echo re-masking (response). If a response body echoes the real token
//     we swapped in, it is re-masked before it reaches the client. This is
//     best effort, a backstop rather than a guarantee: only text-like
//     bodies known to be at most echoMaxBytes are scanned. Larger bodies,
//     bodies of unknown length (chunked, HTTP/2 without Content-Length),
//     SSE streams and binary types (git packfiles) pass through unscanned. Failing closed
//     on those would block every git fetch and clone, and GitHub does not
//     echo OAuth tokens back in responses.
//  4. Refresh (request). GitHub App user tokens expire and are refreshed
//     by POSTing the refresh_token (masked at issuance, step 1) back to the
//     issuance endpoint. The mask is swapped for the real refresh token in
//     the query string or a form/JSON body, inside TLS only.
//
// OAuth refresh tokens (Claude, Codex), configured per provider:
//
//   - Response: a real refresh_token in the JSON body is masked. Covers first
//     issuance and every rotated token on refresh.
//   - Request: a masked refresh_token in the JSON body is swapped back for
//     the real value before the refresh goes upstream.
//
// Fail posture (same as the Python addons):
//
//   - Masking (responses): if a real credential cannot be masked, the
//     response is REPLACED with a 500 so the login/refresh fails loudly. A
//     real credential never reaches the client.
//   - Swapping (requests): if the store errors, the mask is left in place.
//     It goes upstream, earns a clean 401, and nothing leaks.
//   - Swapping happens only inside TLS. Every rule that swaps a real
//     credential in is compiled with require_tls, whatever the config says,
//     so a plain-HTTP request keeps its mask and a real credential is never
//     sent in clear text. Masking (responses) still runs on plain HTTP: it is
//     the safe direction.
//
// iron-proxy never decompresses bodies, so this transform narrows
// Accept-Encoding on the requests whose responses it must read, and decodes
// gzip itself. A body in any other encoding on an issuance/refresh endpoint
// fails closed.
//
// Example config:
//
//	transforms:
//	  - name: credential_mask
//	    config:
//	      store_dir: /var/lib/iron-proxy/credmask
//	      enforce_source: true
//	      github:
//	        consume_rules:
//	          - host: github.com
//	          - host: api.github.com
//	        issue_rules:
//	          - host: github.com
//	            methods: [POST]
//	            paths: [/login/oauth/access_token]
//	      oauth_refresh:
//	        - kind: "claude:refresh"
//	          mask_prefix: "sk-ant-ort01-"
//	          rules:
//	            - host: platform.claude.com
//	              methods: [POST]
//	              paths: [/v1/oauth/token]
//	        - kind: "codex:refresh"
//	          mask_prefix: "rt.1."
//	          rules:
//	            # Whole host, as the Python addon did: Codex uses more than
//	            # one token path (/oauth/token and a deviceauth endpoint).
//	            - host: auth.openai.com
//	              methods: [POST]
package credmask

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("credential_mask", factory)
}

// githubTokenPrefixes are the token kinds gh issues.
var githubTokenPrefixes = []string{"gho_", "ghu_", "ghs_", "ghr_", "ghp_"}

// githubTokenFields are the issuance body fields that may hold a token.
var githubTokenFields = []string{"access_token", "refresh_token"}

// githubAuthKind is the only kind swapped into an Authorization header: a
// masked GitHub access token. A GitHub refresh token, or another provider's
// credential, is never sent there.
const githubAuthKind = "github:access_token"

// Echo re-masking only scans small, text-like responses. Packfiles and other
// large/binary bodies won't echo a token, and reading them would buffer them
// in memory. text/event-stream is excluded so streams are never buffered.
// Anything skipped is forwarded unscanned, not rejected: see the package doc.
const echoMaxBytes = 256 * 1024

var echoTextContentTypes = []string{"application/json", "text/", "application/x-www-form-urlencoded"}

type config struct {
	StoreDir      string               `yaml:"store_dir"`
	EnforceSource *bool                `yaml:"enforce_source,omitempty"` // default true
	GitHub        *githubConfig        `yaml:"github,omitempty"`
	OAuthRefresh  []oauthRefreshConfig `yaml:"oauth_refresh,omitempty"`
}

type githubConfig struct {
	ConsumeRules []hostmatch.RuleConfig `yaml:"consume_rules"`
	IssueRules   []hostmatch.RuleConfig `yaml:"issue_rules"`
}

type oauthRefreshConfig struct {
	Kind       string                 `yaml:"kind"`
	Field      string                 `yaml:"field,omitempty"` // default refresh_token
	MaskPrefix string                 `yaml:"mask_prefix"`
	Rules      []hostmatch.RuleConfig `yaml:"rules"`
}

type oauthProvider struct {
	kind       string
	field      string
	maskPrefix string
	rules      []hostmatch.Rule // as configured: response masking
	swapRules  []hostmatch.Rule // require_tls forced on: request swap
}

// CredMask is the transform.
type CredMask struct {
	store         *Store
	enforceSource bool
	logger        *slog.Logger

	githubConsume []hostmatch.Rule // require_tls forced on; nil when github is not configured
	githubIssue   []hostmatch.Rule // as configured: response masking
	githubRefresh []hostmatch.Rule // issue rules with require_tls forced on: refresh_token swap
	oauth         []oauthProvider
}

func factory(node yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c config
	if err := node.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing credential_mask config: %w", err)
	}
	if c.StoreDir == "" {
		return nil, errors.New("credential_mask: store_dir is required")
	}
	// Fail loud at load if the store is unavailable: running without it
	// would either leak real tokens (issuance) or break all auth (consume).
	store, err := OpenShared(c.StoreDir)
	if err != nil {
		return nil, fmt.Errorf("credential_mask: %w", err)
	}
	return newFromConfig(c, store, logger)
}

func newFromConfig(c config, store *Store, logger *slog.Logger) (*CredMask, error) {
	if logger == nil {
		logger = slog.Default()
	}
	m := &CredMask{
		store:         store,
		enforceSource: c.EnforceSource == nil || *c.EnforceSource,
		logger:        logger,
	}

	if c.GitHub != nil {
		if len(c.GitHub.ConsumeRules) == 0 || len(c.GitHub.IssueRules) == 0 {
			return nil, errors.New("credential_mask: github needs both consume_rules and issue_rules")
		}
		var err error
		if m.githubConsume, err = hostmatch.CompileRulesAllowRequireTLS(withRequireTLS(c.GitHub.ConsumeRules), "credential_mask github.consume_rules"); err != nil {
			return nil, err
		}
		if m.githubIssue, err = hostmatch.CompileRules(c.GitHub.IssueRules, "credential_mask github.issue_rules"); err != nil {
			return nil, err
		}
		if m.githubRefresh, err = hostmatch.CompileRulesAllowRequireTLS(withRequireTLS(c.GitHub.IssueRules), "credential_mask github.issue_rules"); err != nil {
			return nil, err
		}
	}

	for i, p := range c.OAuthRefresh {
		ctx := fmt.Sprintf("credential_mask oauth_refresh[%d]", i)
		if p.Kind == "" {
			return nil, fmt.Errorf("%s: kind is required", ctx)
		}
		if p.MaskPrefix == "" {
			return nil, fmt.Errorf("%s: mask_prefix is required", ctx)
		}
		if len(p.Rules) == 0 {
			return nil, fmt.Errorf("%s: rules are required", ctx)
		}
		rules, err := hostmatch.CompileRules(p.Rules, ctx)
		if err != nil {
			return nil, err
		}
		swapRules, err := hostmatch.CompileRulesAllowRequireTLS(withRequireTLS(p.Rules), ctx)
		if err != nil {
			return nil, err
		}
		field := p.Field
		if field == "" {
			field = "refresh_token"
		}
		m.oauth = append(m.oauth, oauthProvider{kind: p.Kind, field: field, maskPrefix: p.MaskPrefix, rules: rules, swapRules: swapRules})
	}

	if m.githubConsume == nil && len(m.oauth) == 0 {
		return nil, errors.New("credential_mask: configure github and/or oauth_refresh")
	}
	return m, nil
}

// withRequireTLS returns a copy of rules with require_tls forced on. Every
// rule that swaps a real credential into a request goes through it, so the
// guard cannot be configured away.
func withRequireTLS(rules []hostmatch.RuleConfig) []hostmatch.RuleConfig {
	out := make([]hostmatch.RuleConfig, len(rules))
	for i, rc := range rules {
		rc.RequireTLS = true
		out[i] = rc
	}
	return out
}

func (m *CredMask) Name() string { return "credential_mask" }

// sourceOf is the client identity a mask is bound to: the client's IP.
func sourceOf(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

func (m *CredMask) matchingOAuth(req *http.Request) *oauthProvider {
	for i := range m.oauth {
		if hostmatch.MatchAnyRule(m.oauth[i].rules, req) {
			return &m.oauth[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Request side
// ---------------------------------------------------------------------------

func (m *CredMask) TransformRequest(_ context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	cont := &transform.TransformResult{Action: transform.ActionContinue}

	if m.githubConsume != nil && hostmatch.MatchAnyRule(m.githubIssue, req) {
		// We must read the issuance response, so ask for it uncompressed.
		req.Header.Set("Accept-Encoding", "identity")
	}

	if m.githubConsume != nil && hostmatch.MatchAnyRule(m.githubRefresh, req) {
		m.swapGitHubRefresh(tctx, req)
	}

	if m.githubConsume != nil && hostmatch.MatchAnyRule(m.githubConsume, req) {
		m.swapGitHubAuth(tctx, req)
	}

	if p := m.matchingOAuth(req); p != nil {
		// Asked for uncompressed on plain HTTP too: the response is still masked.
		req.Header.Set("Accept-Encoding", "identity")
		if hostmatch.MatchAnyRule(p.swapRules, req) {
			m.swapOAuthRefresh(tctx, req, p)
		}
	}

	return cont, nil
}

// swapGitHubAuth replaces a mask in the Authorization header with the real
// token. Headers only: the body is never read, so large uploads stream.
func (m *CredMask) swapGitHubAuth(tctx *transform.TransformContext, req *http.Request) {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		return
	}
	scheme, value, ok := strings.Cut(auth, " ")
	if !ok {
		return
	}
	value = strings.TrimSpace(value)
	source := sourceOf(req)

	var newAuth string
	switch strings.ToLower(scheme) {
	case "token", "bearer":
		real, found, err := m.store.Resolve(value, githubAuthKind, source, m.enforceSource)
		if err != nil {
			// Fail safe: leave the mask; upstream answers 401, nothing leaks.
			m.logger.Error("credential_mask: store error resolving github mask, header left unchanged", slog.String("error", err.Error()))
			tctx.Annotate("resolve_error", "github")
			return
		}
		if !found {
			return
		}
		newAuth = scheme + " " + real

	case "basic":
		// git-over-HTTPS sends the token as the Basic-auth password.
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return
		}
		user, pw, ok := strings.Cut(string(decoded), ":")
		if !ok {
			return
		}
		real, found, err := m.store.Resolve(pw, githubAuthKind, source, m.enforceSource)
		if err != nil {
			m.logger.Error("credential_mask: store error resolving github basic-auth mask, header left unchanged", slog.String("error", err.Error()))
			tctx.Annotate("resolve_error", "github")
			return
		}
		if !found {
			return
		}
		newAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+real))

	default:
		return
	}

	req.Header.Set("Authorization", newAuth)
	// The response may echo the real token and we will need to read it.
	// Keep compression only if it is gzip, which we can decode.
	narrowAcceptEncodingToGzip(req)
	tctx.Annotate("swapped", "github:authorization")
}

// swapOAuthRefresh replaces a masked refresh token in a JSON request body.
func (m *CredMask) swapOAuthRefresh(tctx *transform.TransformContext, req *http.Request, p *oauthProvider) {
	if req.Body == nil || req.Header.Get("Content-Encoding") != "" {
		return
	}
	data, err := io.ReadAll(req.Body)
	if err != nil || len(data) == 0 {
		return
	}
	obj, ok := parseJSONObject(data)
	if !ok {
		return
	}
	val, ok := obj[p.field].(string)
	if !ok || val == "" {
		return
	}
	real, found, err := m.store.Resolve(val, p.kind, sourceOf(req), m.enforceSource)
	if err != nil {
		// Fail safe: leave the mask; the refresh is rejected and the user re-auths.
		m.logger.Error("credential_mask: store error resolving refresh mask, left unchanged",
			slog.String("kind", p.kind), slog.String("error", err.Error()))
		tctx.Annotate("resolve_error", p.kind)
		return
	}
	if !found {
		return
	}
	obj[p.field] = real
	out, err := encodeJSON(obj)
	if err != nil {
		m.logger.Error("credential_mask: re-encoding refresh request failed, left unchanged",
			slog.String("kind", p.kind), slog.String("error", err.Error()))
		return
	}
	req.Body = transform.NewBufferedBodyFromBytes(out)
	req.ContentLength = int64(len(out))
	req.Header.Set("Content-Length", strconv.Itoa(len(out)))
	tctx.Annotate("swapped", p.kind)
}

// githubRefreshKind is the kind swapped back into a GitHub token refresh
// (grant_type=refresh_token). GitHub documents the refresh_token as a query
// parameter; clients also send it in a form or JSON body. All three are
// handled. The query is safe to rewrite: the audit log records the path
// only, never the query.
const githubRefreshKind = "github:refresh_token"

// swapGitHubRefresh replaces a masked GitHub refresh token with the real one
// in a refresh request to the issuance endpoint. Without it, GitHub App user
// tokens (which expire) could never be refreshed through the proxy.
func (m *CredMask) swapGitHubRefresh(tctx *transform.TransformContext, req *http.Request) {
	source := sourceOf(req)
	swapped := false

	// 1. Query string.
	query := req.URL.Query()
	if mask := query.Get("refresh_token"); mask != "" {
		real, found, err := m.store.Resolve(mask, githubRefreshKind, source, m.enforceSource)
		if err != nil {
			m.logger.Error("credential_mask: store error resolving github refresh mask in query, left unchanged", slog.String("error", err.Error()))
			tctx.Annotate("resolve_error", githubRefreshKind)
			return
		}
		if found {
			query.Set("refresh_token", real)
			req.URL.RawQuery = query.Encode()
			swapped = true
		}
	}

	// 2. Body: form-encoded or JSON.
	if req.Body != nil && req.Header.Get("Content-Encoding") == "" {
		data, err := io.ReadAll(req.Body)
		if err == nil && len(data) > 0 {
			out, bodySwapped, err := m.swapGitHubRefreshInBody(req.Header.Get("Content-Type"), data, source)
			if err != nil {
				m.logger.Error("credential_mask: swapping github refresh mask in body failed, left unchanged", slog.String("error", err.Error()))
				tctx.Annotate("resolve_error", githubRefreshKind)
				return
			}
			if bodySwapped {
				req.Body = transform.NewBufferedBodyFromBytes(out)
				req.ContentLength = int64(len(out))
				req.Header.Set("Content-Length", strconv.Itoa(len(out)))
				swapped = true
			}
		}
	}

	if swapped {
		tctx.Annotate("swapped", githubRefreshKind)
	}
}

// swapGitHubRefreshInBody returns the body with a masked refresh_token
// replaced by the real one. swapped=false means the body had no mask of
// ours and must be left as it was.
func (m *CredMask) swapGitHubRefreshInBody(contentType string, data []byte, source string) ([]byte, bool, error) {
	if strings.Contains(contentType, "application/json") || bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		obj, ok := parseJSONObject(data)
		if !ok {
			return nil, false, nil
		}
		mask, ok := obj["refresh_token"].(string)
		if !ok || mask == "" {
			return nil, false, nil
		}
		real, found, err := m.store.Resolve(mask, githubRefreshKind, source, m.enforceSource)
		if err != nil || !found {
			return nil, false, err
		}
		obj["refresh_token"] = real
		out, err := encodeJSON(obj)
		if err != nil {
			return nil, false, err
		}
		return out, true, nil
	}

	form, err := url.ParseQuery(string(data))
	if err != nil {
		return nil, false, nil
	}
	mask := form.Get("refresh_token")
	if mask == "" {
		return nil, false, nil
	}
	real, found, err := m.store.Resolve(mask, githubRefreshKind, source, m.enforceSource)
	if err != nil || !found {
		return nil, false, err
	}
	form.Set("refresh_token", real)
	return []byte(form.Encode()), true, nil
}

// narrowAcceptEncodingToGzip keeps gzip if the client offered it, otherwise
// asks for identity. Leaves a request with no Accept-Encoding alone.
func narrowAcceptEncodingToGzip(req *http.Request) {
	ae := req.Header.Get("Accept-Encoding")
	if ae == "" {
		return
	}
	if strings.Contains(strings.ToLower(ae), "gzip") {
		req.Header.Set("Accept-Encoding", "gzip")
		return
	}
	req.Header.Set("Accept-Encoding", "identity")
}

// ---------------------------------------------------------------------------
// Response side
// ---------------------------------------------------------------------------

func (m *CredMask) TransformResponse(_ context.Context, tctx *transform.TransformContext, req *http.Request, resp *http.Response) (*transform.TransformResult, error) {
	cont := &transform.TransformResult{Action: transform.ActionContinue}

	if m.githubConsume != nil && hostmatch.MatchAnyRule(m.githubIssue, req) {
		return m.maskGitHubIssuance(tctx, req, resp), nil
	}

	if m.githubConsume != nil && hostmatch.MatchAnyRule(m.githubConsume, req) {
		m.remaskGitHubEcho(tctx, req, resp)
		return cont, nil
	}

	if p := m.matchingOAuth(req); p != nil {
		return m.maskOAuthRefresh(tctx, req, resp, p), nil
	}

	return cont, nil
}

func (m *CredMask) maskGitHubIssuance(tctx *transform.TransformContext, req *http.Request, resp *http.Response) *transform.TransformResult {
	cont := &transform.TransformResult{Action: transform.ActionContinue}

	// The device flow answers 200 {"error":"authorization_pending"} while
	// waiting; only a 200 can carry a token.
	if resp.StatusCode != http.StatusOK {
		return cont
	}
	body, err := readDecodedBody(resp)
	if err != nil {
		return m.abort(tctx, req, "github:issue", fmt.Sprintf("cannot read issuance response: %v", err))
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return cont
	}

	source := sourceOf(req)
	ctype := resp.Header.Get("Content-Type")
	var out []byte
	changed := false

	if strings.Contains(ctype, "application/json") || bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		obj, ok := parseJSONObject(body)
		if !ok {
			return m.abort(tctx, req, "github:issue", "issuance response is not a JSON object")
		}
		for _, field := range githubTokenFields {
			val, ok := obj[field].(string)
			if !ok || val == "" {
				continue
			}
			if !hasAnyPrefix(val, githubTokenPrefixes) {
				// There IS a token, but with a prefix we don't know. Passing
				// it through would leak it, so abort instead.
				return m.abort(tctx, req, "github:issue", fmt.Sprintf("%s has unexpected shape (unknown prefix)", field))
			}
			mask, err := m.store.Tokenize(val, "github:"+field, source, "")
			if err != nil {
				return m.abort(tctx, req, "github:issue", err.Error())
			}
			obj[field] = mask
			changed = true
		}
		if changed {
			if out, err = encodeJSON(obj); err != nil {
				return m.abort(tctx, req, "github:issue", err.Error())
			}
		}
	} else {
		// form-encoded: access_token=gho_...&token_type=bearer&scope=...
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return m.abort(tctx, req, "github:issue", "issuance response is not form-encoded")
		}
		for _, field := range githubTokenFields {
			val := form.Get(field)
			if val == "" {
				continue
			}
			if !hasAnyPrefix(val, githubTokenPrefixes) {
				return m.abort(tctx, req, "github:issue", fmt.Sprintf("%s has unexpected shape (unknown prefix)", field))
			}
			mask, err := m.store.Tokenize(val, "github:"+field, source, "")
			if err != nil {
				return m.abort(tctx, req, "github:issue", err.Error())
			}
			form.Set(field, mask)
			changed = true
		}
		if changed {
			out = []byte(form.Encode())
		}
	}

	if changed {
		setResponseBody(resp, out)
		m.logger.Info("credential_mask: masked github token in issuance response")
		tctx.Annotate("masked", "github:issue")
	}
	return cont
}

// remaskGitHubEcho re-masks a real token echoed back in a response to a
// request we swapped. Which real token we swapped is re-derived from the
// request's (now real) Authorization header and confirmed against the store.
func (m *CredMask) remaskGitHubEcho(tctx *transform.TransformContext, req *http.Request, resp *http.Response) {
	real := realTokenFromAuth(req.Header.Get("Authorization"))
	if real == "" {
		return
	}
	mask, ok := m.store.MaskFor(real, sourceOf(req))
	if !ok {
		return // not a token we swapped in
	}

	ctype := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ctype, "text/event-stream") || !containsAny(ctype, echoTextContentTypes) {
		return
	}
	// The body must be known to be small BEFORE it is read: the pipeline's
	// BufferedBody reads the whole body into memory on the first Read, so a
	// limited read would not bound memory. The size is known from
	// Content-Length, or from Len() if an earlier transform already read it.
	// Chunked and HTTP/2 responses without Content-Length are skipped.
	size := resp.ContentLength
	if size < 0 && resp.Body != nil {
		size = int64(transform.RequireBufferedBody(resp.Body).Len())
	}
	if size < 0 {
		tctx.Annotate("echo_skipped", "unknown-length")
		return
	}
	if size > echoMaxBytes {
		tctx.Annotate("echo_skipped", "too-large")
		return
	}
	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if enc != "" && enc != "identity" && enc != "gzip" {
		// We narrowed Accept-Encoding to gzip, so this should not happen.
		// Record it rather than guess at the encoding.
		tctx.Annotate("echo_skipped", "content-encoding:"+enc)
		return
	}

	body, err := readDecodedBody(resp)
	if err != nil {
		m.logger.Error("credential_mask: echo re-mask read failed", slog.String("error", err.Error()))
		return
	}
	if !bytes.Contains(body, []byte(real)) {
		return
	}
	setResponseBody(resp, bytes.ReplaceAll(body, []byte(real), []byte(mask)))
	m.logger.Info("credential_mask: re-masked echoed github token in response")
	tctx.Annotate("remasked", "github:echo")
}

func (m *CredMask) maskOAuthRefresh(tctx *transform.TransformContext, req *http.Request, resp *http.Response, p *oauthProvider) *transform.TransformResult {
	cont := &transform.TransformResult{Action: transform.ActionContinue}

	body, err := readDecodedBody(resp)
	if err != nil {
		return m.abort(tctx, req, p.kind, fmt.Sprintf("cannot read token response: %v", err))
	}
	obj, ok := parseJSONObject(body)
	if !ok {
		return cont // not a JSON token response (error page, other endpoint)
	}
	val, ok := obj[p.field].(string)
	if !ok || val == "" {
		return cont
	}
	if !strings.HasPrefix(val, p.maskPrefix) {
		// There IS a refresh token, but not in the shape we expect. Passing
		// it through would leak it, so abort instead.
		return m.abort(tctx, req, p.kind, "refresh token has unexpected shape (prefix mismatch)")
	}
	if m.store.IsMask(val) {
		return cont // already a mask; never mask a mask
	}
	mask, err := m.store.Tokenize(val, p.kind, sourceOf(req), p.maskPrefix)
	if err != nil {
		return m.abort(tctx, req, p.kind, err.Error())
	}
	obj[p.field] = mask
	out, err := encodeJSON(obj)
	if err != nil {
		return m.abort(tctx, req, p.kind, err.Error())
	}
	setResponseBody(resp, out)
	m.logger.Info("credential_mask: masked refresh token in response", slog.String("kind", p.kind))
	tctx.Annotate("masked", p.kind)
	return cont
}

// abort replaces the upstream response with a 500 so a login/refresh fails
// loudly rather than letting a real credential reach the client.
func (m *CredMask) abort(tctx *transform.TransformContext, req *http.Request, kind, reason string) *transform.TransformResult {
	m.logger.Error("credential_mask: failed to mask credential, aborting flow",
		slog.String("kind", kind), slog.String("reason", reason))
	tctx.Annotate("aborted", kind)
	tctx.Annotate("abort_reason", reason)

	msg := []byte("credential_mask: failed to mask credential; flow aborted\n")
	return &transform.TransformResult{
		Action: transform.ActionReject,
		Response: &http.Response{
			StatusCode:    http.StatusInternalServerError,
			Status:        "500 Internal Server Error",
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
			Body:          transform.NewBufferedBodyFromBytes(msg),
			ContentLength: int64(len(msg)),
			Request:       req,
		},
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// readDecodedBody reads the response body and undoes gzip if present. The
// pipeline rewinds the buffered body for the next transform, so reading it
// here is safe. Any encoding other than gzip/identity is an error.
func readDecodedBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	switch enc {
	case "", "identity":
		return raw, nil
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer zr.Close()
		return io.ReadAll(zr)
	default:
		return nil, fmt.Errorf("unsupported Content-Encoding %q", enc)
	}
}

// setResponseBody replaces the body with plain (uncompressed) bytes and
// makes every length/encoding header agree with them. The proxy also sets
// Content-Length from a buffered body when it writes the response; setting
// it here keeps the response correct for any later transform too.
func setResponseBody(resp *http.Response, data []byte) {
	resp.Body = transform.NewBufferedBodyFromBytes(data)
	resp.ContentLength = int64(len(data))
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Transfer-Encoding")
	resp.Header.Set("Content-Length", strconv.Itoa(len(data)))
	resp.TransferEncoding = nil
	resp.Uncompressed = false
}

// realTokenFromAuth pulls the credential out of a token/Bearer/Basic header.
func realTokenFromAuth(auth string) string {
	scheme, value, ok := strings.Cut(auth, " ")
	if !ok {
		return ""
	}
	value = strings.TrimSpace(value)
	switch strings.ToLower(scheme) {
	case "token", "bearer":
		return value
	case "basic":
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return ""
		}
		_, pw, ok := strings.Cut(string(decoded), ":")
		if !ok {
			return ""
		}
		return pw
	}
	return ""
}

// parseJSONObject decodes a JSON object, keeping numbers exact.
func parseJSONObject(data []byte) (map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return nil, false
	}
	return obj, true
}

// encodeJSON encodes without HTML escaping and without a trailing newline.
func encodeJSON(obj map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
