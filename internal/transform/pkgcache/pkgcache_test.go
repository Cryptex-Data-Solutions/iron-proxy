package pkgcache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// memStore is an in-memory store with S3's contract: Put stores nothing
// unless it read exactly size bytes without an error.
type memStore struct {
	mu        sync.Mutex
	objects   map[string][]byte
	types     map[string]string
	puts      int
	putErrors int

	getErr   error         // returned by every Get when set
	getBlock bool          // Get waits for its context to end
	putGate  chan struct{} // when set, Put waits for it before reading
	closed   int           // hit bodies closed
}

func newMemStore() *memStore {
	return &memStore{objects: map[string][]byte{}, types: map[string]string{}}
}

func (m *memStore) Get(ctx context.Context, key string) (*object, error) {
	if m.getBlock {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if m.getErr != nil {
		return nil, m.getErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.objects[key]
	if !ok {
		return nil, errNotFound
	}
	return &object{
		Body:        &trackedBody{Reader: bytes.NewReader(data), onClose: m.noteClose},
		Size:        int64(len(data)),
		ContentType: m.types[key],
	}, nil
}

func (m *memStore) noteClose() {
	m.mu.Lock()
	m.closed++
	m.mu.Unlock()
}

func (m *memStore) Put(ctx context.Context, key string, body io.Reader, size int64, contentType string) error {
	m.mu.Lock()
	m.puts++
	gate := m.putGate
	m.mu.Unlock()
	if gate != nil {
		<-gate
	}
	data, err := io.ReadAll(body)
	if err == nil && int64(len(data)) != size {
		err = fmt.Errorf("read %d bytes, want %d", len(data), size)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.putErrors++
		return err
	}
	m.objects[key] = data
	m.types[key] = contentType
	return nil
}

func (m *memStore) stored(key string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.objects[key]
	return data, ok
}

func (m *memStore) counts() (puts, putErrors, closed int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.puts, m.putErrors, m.closed
}

type trackedBody struct {
	io.Reader
	onClose func()
}

func (t *trackedBody) Close() error { t.onClose(); return nil }

func testConfig() config {
	return config{
		Bucket: "test",
		Caches: []cacheConfig{
			{Prefix: "npm", Rules: []hostmatch.RuleConfig{
				{Host: "registry.npmjs.org", Paths: []string{"/*/-/*.tgz", "/@*/*/-/*.tgz"}},
			}},
			{Prefix: "nuget", Rules: []hostmatch.RuleConfig{
				{Host: "api.nuget.org", Paths: []string{"/v3-flatcontainer/*/*/*.nupkg"}},
			}},
		},
	}
}

func newTestCache(t *testing.T, c config, st store) *PkgCache {
	t.Helper()
	p, err := newFromConfig(c, st, nil)
	require.NoError(t, err)
	return p
}

func newRequest(method, rawURL string) *http.Request {
	req := httptest.NewRequest(method, rawURL, nil)
	req.Header.Del("Authorization")
	return req
}

// upstreamResponse is what the proxy hands the response pipeline.
func upstreamResponse(req *http.Request, data []byte, contentLength int64) *http.Response {
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"application/octet-stream"}},
		ContentLength: contentLength,
		Body:          transform.NewBufferedBody(io.NopCloser(bytes.NewReader(data)), 0),
		Request:       req,
	}
}

// clientReads reads the final response the way the proxy's writeResponse does.
func clientReads(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	data, err := io.ReadAll(transform.RequireBufferedBody(resp.Body).StreamingReader())
	require.NoError(t, err)
	return data
}

func runRequest(t *testing.T, p *PkgCache, req *http.Request) (*transform.TransformResult, map[string]any) {
	t.Helper()
	tctx := &transform.TransformContext{}
	res, err := p.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	return res, tctx.DrainAnnotations()
}

func runResponse(t *testing.T, p *PkgCache, req *http.Request, resp *http.Response) map[string]any {
	t.Helper()
	tctx := &transform.TransformContext{}
	res, err := p.TransformResponse(context.Background(), tctx, req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	return tctx.DrainAnnotations()
}

func TestCacheKey(t *testing.T) {
	p := newTestCache(t, testConfig(), newMemStore())

	cases := []struct {
		name    string
		method  string
		url     string
		headers map[string]string
		wantKey string
	}{
		{"npm tarball", "GET", "https://registry.npmjs.org/react/-/react-18.3.1.tgz", nil,
			"npm/registry.npmjs.org/react/-/react-18.3.1.tgz"},
		{"npm scoped tarball", "GET", "https://registry.npmjs.org/@babel/core/-/core-7.26.0.tgz", nil,
			"npm/registry.npmjs.org/@babel/core/-/core-7.26.0.tgz"},
		{"nuget package", "GET", "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg", nil,
			"nuget/api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"},
		{"npm version list (metadata)", "GET", "https://registry.npmjs.org/react", nil, ""},
		{"nuget version list (metadata)", "GET", "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json", nil, ""},
		{"other host", "GET", "https://example.com/react/-/react-18.3.1.tgz", nil, ""},
		{"POST", "POST", "https://registry.npmjs.org/react/-/react-18.3.1.tgz", nil, ""},
		{"HEAD", "HEAD", "https://registry.npmjs.org/react/-/react-18.3.1.tgz", nil, ""},
		{"query string", "GET", "https://registry.npmjs.org/react/-/react-18.3.1.tgz?x=1", nil, ""},
		{"authorization", "GET", "https://registry.npmjs.org/react/-/react-18.3.1.tgz",
			map[string]string{"Authorization": "Bearer secret"}, ""},
		{"cookie", "GET", "https://registry.npmjs.org/react/-/react-18.3.1.tgz",
			map[string]string{"Cookie": "a=b"}, ""},
		{"range", "GET", "https://registry.npmjs.org/react/-/react-18.3.1.tgz",
			map[string]string{"Range": "bytes=0-10"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := newRequest(tc.method, tc.url)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			key, _ := p.cacheKey(req)
			require.Equal(t, tc.wantKey, key)
		})
	}
}

func TestHit_ServedFromStore(t *testing.T) {
	st := newMemStore()
	key := "npm/registry.npmjs.org/react/-/react-18.3.1.tgz"
	st.objects[key] = []byte("tarball bytes")
	st.types[key] = "application/octet-stream"
	p := newTestCache(t, testConfig(), st)

	res, ann := runRequest(t, p, newRequest("GET", "https://registry.npmjs.org/react/-/react-18.3.1.tgz"))

	require.Equal(t, transform.ActionStub, res.Action)
	require.Equal(t, "hit", ann["pkgcache"])
	require.Equal(t, http.StatusOK, res.Response.StatusCode)
	require.Equal(t, "13", res.Response.Header.Get("Content-Length"))
	require.Equal(t, "hit", res.Response.Header.Get("X-Iron-Pkgcache"))

	// The proxy copies a stub's body without closing it: it must close
	// itself at the end of the stream.
	data, err := io.ReadAll(res.Response.Body)
	require.NoError(t, err)
	require.Equal(t, "tarball bytes", string(data))
	_, _, closed := st.counts()
	require.Equal(t, 1, closed)
}

func TestMiss_StoredWhileStreaming(t *testing.T) {
	st := newMemStore()
	p := newTestCache(t, testConfig(), st)
	req := newRequest("GET", "https://api.nuget.org/v3-flatcontainer/a/1.0.0/a.1.0.0.nupkg")
	payload := bytes.Repeat([]byte("nupkg"), 100_000) // 500 KB

	res, ann := runRequest(t, p, req)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "miss", ann["pkgcache"])

	resp := upstreamResponse(req, payload, int64(len(payload)))
	ann = runResponse(t, p, req, resp)
	require.Equal(t, "started", ann["pkgcache_store"])

	require.Equal(t, payload, clientReads(t, resp), "the client gets the response unchanged")

	key := "nuget/api.nuget.org/v3-flatcontainer/a/1.0.0/a.1.0.0.nupkg"
	require.Eventually(t, func() bool { _, ok := st.stored(key); return ok }, 2*time.Second, 5*time.Millisecond)
	data, _ := st.stored(key)
	require.Equal(t, payload, data)

	// The next request is a hit.
	res, ann = runRequest(t, p, newRequest("GET", "https://api.nuget.org/v3-flatcontainer/a/1.0.0/a.1.0.0.nupkg"))
	require.Equal(t, transform.ActionStub, res.Action)
	require.Equal(t, "hit", ann["pkgcache"])
}

func TestMiss_ShortBodyIsNotStored(t *testing.T) {
	st := newMemStore()
	p := newTestCache(t, testConfig(), st)
	req := newRequest("GET", "https://registry.npmjs.org/react/-/react-18.3.1.tgz")

	// Content-Length promises more than the registry sends.
	resp := upstreamResponse(req, []byte("only part"), 1000)
	runResponse(t, p, req, resp)
	require.Equal(t, "only part", string(clientReads(t, resp)))

	require.Eventually(t, func() bool { _, errs, _ := st.counts(); return errs == 1 }, 2*time.Second, 5*time.Millisecond)
	_, ok := st.stored("npm/registry.npmjs.org/react/-/react-18.3.1.tgz")
	require.False(t, ok, "a partial download must never be stored")
}

func TestStoreDown_FailsOpen(t *testing.T) {
	st := newMemStore()
	st.getErr = errors.New("s3 unavailable")
	p := newTestCache(t, testConfig(), st)

	res, ann := runRequest(t, p, newRequest("GET", "https://registry.npmjs.org/react/-/react-18.3.1.tgz"))
	require.Equal(t, transform.ActionContinue, res.Action, "the request goes to the registry")
	require.Equal(t, "lookup_error", ann["pkgcache"])
}

func TestLookupTimeout_FailsOpen(t *testing.T) {
	st := newMemStore()
	st.getBlock = true
	c := testConfig()
	c.LookupTimeout = 50 * time.Millisecond
	p := newTestCache(t, c, st)

	started := time.Now()
	res, ann := runRequest(t, p, newRequest("GET", "https://registry.npmjs.org/react/-/react-18.3.1.tgz"))
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "lookup_error", ann["pkgcache"])
	require.Less(t, time.Since(started), time.Second)
}

func TestSlowStore_NeverSlowsTheClient(t *testing.T) {
	st := newMemStore()
	st.putGate = make(chan struct{}) // Put can't read until we say so
	c := testConfig()
	c.MaxQueuedBytes = 64 << 10
	p := newTestCache(t, c, st)
	req := newRequest("GET", "https://registry.npmjs.org/react/-/react-18.3.1.tgz")
	payload := bytes.Repeat([]byte("x"), 1<<20) // 1 MiB, far more than the queue

	resp := upstreamResponse(req, payload, int64(len(payload)))
	runResponse(t, p, req, resp)

	done := make(chan []byte)
	go func() { done <- clientReads(t, resp) }()
	select {
	case data := <-done:
		require.Equal(t, payload, data)
	case <-time.After(2 * time.Second):
		t.Fatal("the client was held up by a stuck store")
	}

	close(st.putGate)
	require.Eventually(t, func() bool { _, errs, _ := st.counts(); return errs == 1 }, 2*time.Second, 5*time.Millisecond)
	_, ok := st.stored("npm/registry.npmjs.org/react/-/react-18.3.1.tgz")
	require.False(t, ok)
}

func TestClientStopsReading_UploadAbandoned(t *testing.T) {
	st := newMemStore()
	c := testConfig()
	c.UploadIdleTimeout = 50 * time.Millisecond
	p := newTestCache(t, c, st)
	req := newRequest("GET", "https://registry.npmjs.org/react/-/react-18.3.1.tgz")
	payload := bytes.Repeat([]byte("y"), 100_000)

	resp := upstreamResponse(req, payload, int64(len(payload)))
	runResponse(t, p, req, resp)

	// Read part of it, then stop, as a disconnected client would.
	reader := transform.RequireBufferedBody(resp.Body).StreamingReader()
	_, err := io.ReadFull(reader, make([]byte, 1000))
	require.NoError(t, err)

	require.Eventually(t, func() bool { _, errs, _ := st.counts(); return errs == 1 }, 2*time.Second, 5*time.Millisecond)
	_, ok := st.stored("npm/registry.npmjs.org/react/-/react-18.3.1.tgz")
	require.False(t, ok)
}

func TestResponsesThatMustNotBeStored(t *testing.T) {
	cases := []struct {
		name   string
		modify func(*http.Response)
		reason string
	}{
		{"404", func(r *http.Response) { r.StatusCode = http.StatusNotFound }, "skipped: status 404"},
		{"304", func(r *http.Response) { r.StatusCode = http.StatusNotModified }, "skipped: status 304"},
		{"compressed", func(r *http.Response) { r.Header.Set("Content-Encoding", "gzip") }, "skipped: content-encoding gzip"},
		{"no length", func(r *http.Response) { r.ContentLength = -1 }, "skipped: no Content-Length"},
		{"private", func(r *http.Response) { r.Header.Set("Cache-Control", "private, max-age=0") }, "skipped: Cache-Control private, max-age=0"},
		{"sets cookie", func(r *http.Response) { r.Header.Set("Set-Cookie", "a=b") }, "skipped: sets a cookie"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newMemStore()
			p := newTestCache(t, testConfig(), st)
			req := newRequest("GET", "https://registry.npmjs.org/react/-/react-18.3.1.tgz")
			resp := upstreamResponse(req, []byte("data"), 4)
			tc.modify(resp)

			ann := runResponse(t, p, req, resp)
			require.Equal(t, tc.reason, ann["pkgcache_store"])
			require.Equal(t, "data", string(clientReads(t, resp)))
			puts, _, _ := st.counts()
			require.Equal(t, 0, puts)
		})
	}
}

func TestTooManyUploads_Skipped(t *testing.T) {
	st := newMemStore()
	st.putGate = make(chan struct{})
	defer close(st.putGate)
	c := testConfig()
	c.MaxConcurrentUploads = 1
	p := newTestCache(t, c, st)

	req1 := newRequest("GET", "https://registry.npmjs.org/a/-/a-1.0.0.tgz")
	runResponse(t, p, req1, upstreamResponse(req1, []byte("aaaa"), 4))

	req2 := newRequest("GET", "https://registry.npmjs.org/b/-/b-1.0.0.tgz")
	ann := runResponse(t, p, req2, upstreamResponse(req2, []byte("bbbb"), 4))
	require.Equal(t, "skipped: too many uploads running", ann["pkgcache_store"])
}

func TestConfig_Validation(t *testing.T) {
	st := newMemStore()

	_, err := newFromConfig(config{Bucket: "b"}, st, nil)
	require.ErrorContains(t, err, "at least one cache")

	_, err = newFromConfig(config{Bucket: "b", Caches: []cacheConfig{
		{Prefix: "npm", Rules: []hostmatch.RuleConfig{{Host: "registry.npmjs.org"}}},
	}}, st, nil)
	require.ErrorContains(t, err, "paths are required")

	_, err = newFromConfig(config{Bucket: "b", Caches: []cacheConfig{
		{Rules: []hostmatch.RuleConfig{{Host: "registry.npmjs.org", Paths: []string{"/*/-/*.tgz"}}}},
	}}, st, nil)
	require.ErrorContains(t, err, "prefix is required")

	_, err = newFromConfig(config{Bucket: "b", Caches: []cacheConfig{
		{Prefix: "npm", Rules: []hostmatch.RuleConfig{{Host: "registry.npmjs.org", Paths: []string{"/*/-/*.tgz"}}}},
		{Prefix: "npm/", Rules: []hostmatch.RuleConfig{{Host: "registry.yarnpkg.com", Paths: []string{"/*/-/*.tgz"}}}},
	}}, st, nil)
	require.ErrorContains(t, err, "used twice")
}
