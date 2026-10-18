package credmask

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

const (
	clientIP    = "10.0.0.5"
	clientAddr  = clientIP + ":54321"
	realClaude  = "sk-ant-ort01-REALrefreshTOKENvalue0123456789"
	realCodex   = "rt.1.REALcodexREFRESHtoken0123456789"
	issuePath   = "https://github.com/login/oauth/access_token"
	githubAPI   = "https://api.github.com/user"
	claudeToken = "https://platform.claude.com/v1/oauth/token"
)

func newTestTransform(t *testing.T) (*CredMask, *Store) {
	t.Helper()
	store := newTestStore(t)
	c := config{
		StoreDir: "unused-in-tests",
		GitHub: &githubConfig{
			ConsumeRules: []hostmatch.RuleConfig{{Host: "github.com"}, {Host: "api.github.com"}},
			IssueRules:   []hostmatch.RuleConfig{{Host: "github.com", Methods: []string{"POST"}, Paths: []string{"/login/oauth/access_token"}}},
		},
		OAuthRefresh: []oauthRefreshConfig{
			{Kind: "claude:refresh", MaskPrefix: "sk-ant-ort01-", Rules: []hostmatch.RuleConfig{{Host: "platform.claude.com", Methods: []string{"POST"}, Paths: []string{"/v1/oauth/token"}}}},
			{Kind: "codex:refresh", MaskPrefix: "rt.1.", Rules: []hostmatch.RuleConfig{{Host: "auth.openai.com", Methods: []string{"POST"}}}},
		},
	}
	m, err := newFromConfig(c, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	return m, store
}

func newReq(method, target string, body []byte) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.RemoteAddr = clientAddr
	req.Body = transform.NewBufferedBody(req.Body, 0)
	return req
}

func newResp(req *http.Request, status int, header http.Header, body []byte) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		StatusCode:    status,
		Header:        header,
		Body:          transform.NewBufferedBody(io.NopCloser(bytes.NewReader(body)), 0),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(data)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// readAll reads a body the way the proxy will after the pipeline. The
// pipeline Reset()s every buffered body after each transform
// (pipeline.go ProcessRequest/ProcessResponse); these tests call the
// transform directly, so do the same rewind here first.
func readAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	if b, ok := r.(*transform.BufferedBody); ok {
		b.Reset()
	}
	data, err := io.ReadAll(r)
	require.NoError(t, err)
	return data
}

// requireLengthMatches checks the caveat from the gRPC-plugin discussion:
// after a body rewrite, Content-Length must match the bytes actually sent.
func requireLengthMatches(t *testing.T, resp *http.Response, body []byte) {
	t.Helper()
	require.Equal(t, int64(len(body)), resp.ContentLength)
	require.Equal(t, strconv.Itoa(len(body)), resp.Header.Get("Content-Length"))
	require.Empty(t, resp.Header.Get("Content-Encoding"))
}

func tctx() *transform.TransformContext { return &transform.TransformContext{} }

// ---------------------------------------------------------------------------
// GitHub issuance
// ---------------------------------------------------------------------------

func TestGitHubIssuanceJSONIsMasked(t *testing.T) {
	m, store := newTestTransform(t)
	ctx := context.Background()

	req := newReq("POST", issuePath, []byte("client_id=x&device_code=y"))
	req.Header.Set("Accept-Encoding", "gzip, br")
	res, err := m.TransformRequest(ctx, tctx(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, "identity", req.Header.Get("Accept-Encoding"), "issuance must be requested uncompressed")

	upstream := []byte(`{"access_token":"` + realGitHub + `","token_type":"bearer","scope":"repo"}`)
	resp := newResp(req, 200, http.Header{"Content-Type": {"application/json; charset=utf-8"}}, upstream)
	res, err = m.TransformResponse(ctx, tctx(), req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)

	body := readAll(t, resp.Body)
	require.NotContains(t, string(body), realGitHub)
	requireLengthMatches(t, resp, body)

	var obj map[string]string
	require.NoError(t, json.Unmarshal(body, &obj))
	mask := obj["access_token"]
	require.True(t, strings.HasPrefix(mask, "gho_"))
	require.Len(t, mask, len(realGitHub))
	require.Equal(t, "repo", obj["scope"])

	real, ok, err := store.Resolve(mask, "github:access_token", clientIP, true)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, realGitHub, real)
}

func TestGitHubIssuanceGzipIsDecodedAndMasked(t *testing.T) {
	m, _ := newTestTransform(t)
	req := newReq("POST", issuePath, nil)

	upstream := gzipBytes(t, []byte(`{"access_token":"`+realGitHub+`"}`))
	resp := newResp(req, 200, http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {"gzip"}}, upstream)
	res, err := m.TransformResponse(context.Background(), tctx(), req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)

	body := readAll(t, resp.Body)
	require.NotContains(t, string(body), realGitHub)
	require.Contains(t, string(body), `"access_token":"gho_`)
	requireLengthMatches(t, resp, body)
}

func TestGitHubIssuanceFormIsMasked(t *testing.T) {
	m, _ := newTestTransform(t)
	req := newReq("POST", issuePath, nil)

	upstream := []byte("access_token=" + realGitHub + "&scope=repo&token_type=bearer")
	resp := newResp(req, 200, http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, upstream)
	_, err := m.TransformResponse(context.Background(), tctx(), req, resp)
	require.NoError(t, err)

	body := readAll(t, resp.Body)
	require.NotContains(t, string(body), realGitHub)
	form, err := url.ParseQuery(string(body))
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(form.Get("access_token"), "gho_"))
	require.Equal(t, "repo", form.Get("scope"))
	requireLengthMatches(t, resp, body)
}

func TestGitHubIssuancePendingPassesUntouched(t *testing.T) {
	m, _ := newTestTransform(t)
	req := newReq("POST", issuePath, nil)
	upstream := []byte(`{"error":"authorization_pending"}`)
	resp := newResp(req, 200, http.Header{"Content-Type": {"application/json"}}, upstream)

	res, err := m.TransformResponse(context.Background(), tctx(), req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, upstream, readAll(t, resp.Body))
}

func TestGitHubIssuanceUnreadableEncodingFailsClosed(t *testing.T) {
	m, _ := newTestTransform(t)
	req := newReq("POST", issuePath, nil)
	resp := newResp(req, 200, http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {"br"}}, []byte("opaque"))

	res, err := m.TransformResponse(context.Background(), tctx(), req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
	require.Equal(t, http.StatusInternalServerError, res.Response.StatusCode)
}

func TestGitHubIssuanceStoreFailureFailsClosed(t *testing.T) {
	m, _ := newTestTransform(t)
	// A request with no usable client address has no source identity,
	// so the store refuses to tokenize: the real token must not pass.
	req := newReq("POST", issuePath, nil)
	req.RemoteAddr = ""
	resp := newResp(req, 200, http.Header{"Content-Type": {"application/json"}}, []byte(`{"access_token":"`+realGitHub+`"}`))

	res, err := m.TransformResponse(context.Background(), tctx(), req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
	require.NotContains(t, string(readAll(t, res.Response.Body)), realGitHub)
}

// A token GitHub issues with a prefix we don't recognise is still a real
// credential: the flow must fail closed rather than pass it through.
func TestGitHubIssuanceUnknownPrefix(t *testing.T) {
	const unknown = "ghx_NEWprefixTOKEN0123456789abcdefghij"
	tests := []struct {
		name       string
		ctype      string
		body       string
		wantReject bool
	}{
		{name: "json access_token", ctype: "application/json", body: `{"access_token":"` + unknown + `"}`, wantReject: true},
		{name: "json refresh_token", ctype: "application/json", body: `{"access_token":"` + realGitHub + `","refresh_token":"` + unknown + `"}`, wantReject: true},
		{name: "form access_token", ctype: "application/x-www-form-urlencoded", body: "access_token=" + unknown + "&token_type=bearer", wantReject: true},
		{name: "json empty refresh_token is not a token", ctype: "application/json", body: `{"access_token":"` + realGitHub + `","refresh_token":""}`, wantReject: false},
		{name: "json null refresh_token is not a token", ctype: "application/json", body: `{"access_token":"` + realGitHub + `","refresh_token":null}`, wantReject: false},
		{name: "form empty refresh_token is not a token", ctype: "application/x-www-form-urlencoded", body: "access_token=" + realGitHub + "&refresh_token=", wantReject: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := newTestTransform(t)
			req := newReq("POST", issuePath, nil)
			resp := newResp(req, 200, http.Header{"Content-Type": {tc.ctype}}, []byte(tc.body))

			res, err := m.TransformResponse(context.Background(), tctx(), req, resp)
			require.NoError(t, err)
			if tc.wantReject {
				require.Equal(t, transform.ActionReject, res.Action)
				require.Equal(t, http.StatusInternalServerError, res.Response.StatusCode)
				require.NotContains(t, string(readAll(t, res.Response.Body)), unknown)
				return
			}
			require.Equal(t, transform.ActionContinue, res.Action)
			require.NotContains(t, string(readAll(t, resp.Body)), realGitHub)
		})
	}
}

// ---------------------------------------------------------------------------
// GitHub consumption
// ---------------------------------------------------------------------------

func TestGitHubConsumeSwapsTokenAndBearer(t *testing.T) {
	m, store := newTestTransform(t)
	mask, err := store.Tokenize(realGitHub, "github:access_token", clientIP, "")
	require.NoError(t, err)

	for _, scheme := range []string{"token", "Bearer"} {
		req := newReq("GET", githubAPI, nil)
		req.Header.Set("Authorization", scheme+" "+mask)
		_, err := m.TransformRequest(context.Background(), tctx(), req)
		require.NoError(t, err)
		require.Equal(t, scheme+" "+realGitHub, req.Header.Get("Authorization"))
	}
}

func TestGitHubConsumeSwapsBasicAuthPassword(t *testing.T) {
	m, store := newTestTransform(t)
	mask, err := store.Tokenize(realGitHub, "github:access_token", clientIP, "")
	require.NoError(t, err)

	req := newReq("POST", "https://github.com/org/repo.git/git-receive-pack", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:"+mask)))
	_, err = m.TransformRequest(context.Background(), tctx(), req)
	require.NoError(t, err)

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+realGitHub))
	require.Equal(t, want, req.Header.Get("Authorization"))
}

// The #83 regression: a large git push must keep streaming. The swap is
// header-only, so the transform must never read (buffer) the body.
func TestGitHubConsumeDoesNotReadLargeBody(t *testing.T) {
	m, store := newTestTransform(t)
	mask, err := store.Tokenize(realGitHub, "github:access_token", clientIP, "")
	require.NoError(t, err)

	big := bytes.Repeat([]byte("p"), 8<<20) // 8 MiB pack
	req := newReq("POST", "https://github.com/org/repo.git/git-receive-pack", big)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:"+mask)))

	_, err = m.TransformRequest(context.Background(), tctx(), req)
	require.NoError(t, err)
	require.Contains(t, req.Header.Get("Authorization"), base64.StdEncoding.EncodeToString([]byte("x-access-token:"+realGitHub)))
	require.Equal(t, -1, transform.RequireBufferedBody(req.Body).Len(), "body must not be buffered")
}

func TestGitHubConsumeOtherSourceIsNotSwapped(t *testing.T) {
	m, store := newTestTransform(t)
	mask, err := store.Tokenize(realGitHub, "github:access_token", "10.0.0.99", "")
	require.NoError(t, err)

	req := newReq("GET", githubAPI, nil)
	req.Header.Set("Authorization", "token "+mask)
	_, err = m.TransformRequest(context.Background(), tctx(), req)
	require.NoError(t, err)
	require.Equal(t, "token "+mask, req.Header.Get("Authorization"), "a mask from another box forwards as-is and earns a 401")
}

func TestGitHubConsumeNarrowsAcceptEncoding(t *testing.T) {
	m, store := newTestTransform(t)
	mask, err := store.Tokenize(realGitHub, "github:access_token", clientIP, "")
	require.NoError(t, err)

	req := newReq("GET", githubAPI, nil)
	req.Header.Set("Authorization", "token "+mask)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	_, err = m.TransformRequest(context.Background(), tctx(), req)
	require.NoError(t, err)
	require.Equal(t, "gzip", req.Header.Get("Accept-Encoding"))
}

func TestNonGitHubHostIsUntouched(t *testing.T) {
	m, store := newTestTransform(t)
	mask, err := store.Tokenize(realGitHub, "github:access_token", clientIP, "")
	require.NoError(t, err)

	req := newReq("GET", "https://example.com/", nil)
	req.Header.Set("Authorization", "token "+mask)
	_, err = m.TransformRequest(context.Background(), tctx(), req)
	require.NoError(t, err)
	require.Equal(t, "token "+mask, req.Header.Get("Authorization"), "a mask must never be resolved for a host outside the rules")
}

// ---------------------------------------------------------------------------
// GitHub echo re-masking
// ---------------------------------------------------------------------------

func swappedGitHubRequest(t *testing.T, m *CredMask, store *Store) (*http.Request, string) {
	t.Helper()
	mask, err := store.Tokenize(realGitHub, "github:access_token", clientIP, "")
	require.NoError(t, err)
	req := newReq("GET", githubAPI, nil)
	req.Header.Set("Authorization", "token "+mask)
	_, err = m.TransformRequest(context.Background(), tctx(), req)
	require.NoError(t, err)
	return req, mask
}

func TestEchoIsReMasked(t *testing.T) {
	m, store := newTestTransform(t)
	req, mask := swappedGitHubRequest(t, m, store)

	upstream := []byte(`{"token":"` + realGitHub + `","note":"echo"}`)
	resp := newResp(req, 200, http.Header{"Content-Type": {"application/json"}}, upstream)
	_, err := m.TransformResponse(context.Background(), tctx(), req, resp)
	require.NoError(t, err)

	body := readAll(t, resp.Body)
	require.NotContains(t, string(body), realGitHub)
	require.Contains(t, string(body), mask)
	requireLengthMatches(t, resp, body)
}

func TestEchoGzipIsReMasked(t *testing.T) {
	m, store := newTestTransform(t)
	req, mask := swappedGitHubRequest(t, m, store)

	upstream := gzipBytes(t, []byte(`{"token":"`+realGitHub+`"}`))
	resp := newResp(req, 200, http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {"gzip"}}, upstream)
	_, err := m.TransformResponse(context.Background(), tctx(), req, resp)
	require.NoError(t, err)

	body := readAll(t, resp.Body)
	require.Contains(t, string(body), mask)
	requireLengthMatches(t, resp, body)
}

func TestEchoSkipsEventStreamAndBinary(t *testing.T) {
	m, store := newTestTransform(t)
	for _, ctype := range []string{"text/event-stream", "application/x-git-upload-pack-result"} {
		req, _ := swappedGitHubRequest(t, m, store)
		resp := newResp(req, 200, http.Header{"Content-Type": {ctype}}, []byte("data: "+realGitHub))
		_, err := m.TransformResponse(context.Background(), tctx(), req, resp)
		require.NoError(t, err)
		require.Equal(t, -1, transform.RequireBufferedBody(resp.Body).Len(), ctype+" must not be buffered")
	}
}

// Echo scanning must never buffer a body it cannot first prove is small:
// the pipeline's BufferedBody reads the whole body on the first Read.
func TestEchoSizeBounds(t *testing.T) {
	small := []byte(`{"token":"` + realGitHub + `"}`)
	large := append(bytes.Repeat([]byte(" "), echoMaxBytes), small...)

	tests := []struct {
		name          string
		body          []byte
		unknownLength bool // ContentLength -1, as for chunked or HTTP/2
		preBuffered   bool // an earlier transform already read the body
		wantRemasked  bool
		wantBuffered  bool
	}{
		{name: "known small length", body: small, wantRemasked: true, wantBuffered: true},
		{name: "known large length", body: large, wantRemasked: false, wantBuffered: false},
		{name: "unknown length is not read", body: small, unknownLength: true, wantRemasked: false, wantBuffered: false},
		{name: "unknown length but already buffered small", body: small, unknownLength: true, preBuffered: true, wantRemasked: true, wantBuffered: true},
		{name: "unknown length but already buffered large", body: large, unknownLength: true, preBuffered: true, wantRemasked: false, wantBuffered: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, store := newTestTransform(t)
			req, mask := swappedGitHubRequest(t, m, store)
			resp := newResp(req, 200, http.Header{"Content-Type": {"application/json"}}, tc.body)
			if tc.unknownLength {
				resp.ContentLength = -1
			}
			if tc.preBuffered {
				bb := transform.RequireBufferedBody(resp.Body)
				_, err := io.ReadAll(bb)
				require.NoError(t, err)
				bb.Reset()
			}

			_, err := m.TransformResponse(context.Background(), tctx(), req, resp)
			require.NoError(t, err)

			bb := transform.RequireBufferedBody(resp.Body)
			if !tc.wantBuffered {
				require.Equal(t, -1, bb.Len(), "body must not be buffered")
				return
			}
			out := string(readAll(t, resp.Body))
			if tc.wantRemasked {
				require.NotContains(t, out, realGitHub)
				require.Contains(t, out, mask)
			} else {
				require.Contains(t, out, realGitHub)
			}
		})
	}
}

// A small gzip body can decode to a huge one. The decoded size is bounded
// too: echo skips (the body passes untouched), login/refresh aborts.
func TestDecodedSizeLimits(t *testing.T) {
	echoToken := []byte(`{"token":"` + realGitHub + `"}`)
	echoAtLimit := append(bytes.Repeat([]byte(" "), echoMaxBytes-len(echoToken)), echoToken...)
	echoOverLimit := append(bytes.Repeat([]byte(" "), echoMaxBytes), echoToken...)
	issuanceOverLimit := append(bytes.Repeat([]byte(" "), tokenMaxDecodedBytes), []byte(`{"access_token":"`+realGitHub+`"}`)...)
	oauthOverLimit := append(bytes.Repeat([]byte(" "), tokenMaxDecodedBytes), []byte(`{"refresh_token":"`+realClaude+`"}`)...)

	smallOAuth := []byte(`{"refresh_token":"` + realClaude + `"}`)

	tests := []struct {
		name           string
		kind           string // "echo", "issuance" or "oauth"
		decoded        []byte
		gzip           bool
		declaredLength int64 // 0 = the real length; else overrides Content-Length
		wantReject     bool  // login/refresh: aborted with a 500
		wantUnread     bool  // login/refresh: body never read (rejected on headers alone)
		wantMasked     bool  // echo: real token re-masked
	}{
		{name: "oauth declared length past the limit is not read", kind: "oauth", decoded: smallOAuth, declaredLength: tokenMaxDecodedBytes + 1, wantReject: true, wantUnread: true},
		{name: "echo gzip decodes to exactly the limit", kind: "echo", decoded: echoAtLimit, gzip: true, wantMasked: true},
		{name: "echo gzip decodes past the limit", kind: "echo", decoded: echoOverLimit, gzip: true, wantMasked: false},
		{name: "issuance gzip decodes past the limit", kind: "issuance", decoded: issuanceOverLimit, gzip: true, wantReject: true},
		{name: "issuance plain body past the limit", kind: "issuance", decoded: issuanceOverLimit, gzip: false, wantReject: true},
		{name: "oauth gzip decodes past the limit", kind: "oauth", decoded: oauthOverLimit, gzip: true, wantReject: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, store := newTestTransform(t)

			var req *http.Request
			var mask string
			switch tc.kind {
			case "echo":
				req, mask = swappedGitHubRequest(t, m, store)
			case "issuance":
				req = newReq("POST", issuePath, nil)
			case "oauth":
				req = newReq("POST", claudeToken, nil)
			}

			upstream := tc.decoded
			header := http.Header{"Content-Type": {"application/json"}}
			if tc.gzip {
				upstream = gzipBytes(t, tc.decoded)
				header.Set("Content-Encoding", "gzip")
				require.LessOrEqual(t, len(upstream), echoMaxBytes, "compressed body must pass the compressed-size check")
			}
			resp := newResp(req, 200, header, upstream)
			if tc.declaredLength != 0 {
				resp.ContentLength = tc.declaredLength
			}

			res, err := m.TransformResponse(context.Background(), tctx(), req, resp)
			require.NoError(t, err)

			if tc.kind != "echo" {
				if tc.wantReject {
					require.Equal(t, transform.ActionReject, res.Action)
					require.Equal(t, http.StatusInternalServerError, res.Response.StatusCode)
				}
				if tc.wantUnread {
					require.Equal(t, -1, transform.RequireBufferedBody(resp.Body).Len(), "body must not be read")
				}
				return
			}

			out := readAll(t, resp.Body)
			if tc.wantMasked {
				require.NotContains(t, string(out), realGitHub)
				require.Contains(t, string(out), mask)
			} else {
				require.Equal(t, upstream, out, "skipped: the original compressed body goes through as-is")
			}
		})
	}
}

func TestEchoUnchangedBodyIsLeftAlone(t *testing.T) {
	m, store := newTestTransform(t)
	req, _ := swappedGitHubRequest(t, m, store)

	upstream := gzipBytes(t, []byte(`{"login":"octocat"}`))
	resp := newResp(req, 200, http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {"gzip"}}, upstream)
	_, err := m.TransformResponse(context.Background(), tctx(), req, resp)
	require.NoError(t, err)
	require.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))
	require.Equal(t, upstream, readAll(t, resp.Body), "nothing echoed: the original compressed body goes through as-is")
}

// ---------------------------------------------------------------------------
// OAuth refresh (Claude / Codex)
// ---------------------------------------------------------------------------

func TestOAuthResponseIsMasked(t *testing.T) {
	m, store := newTestTransform(t)
	req := newReq("POST", claudeToken, []byte(`{"grant_type":"authorization_code"}`))
	_, err := m.TransformRequest(context.Background(), tctx(), req)
	require.NoError(t, err)
	require.Equal(t, "identity", req.Header.Get("Accept-Encoding"))

	upstream := []byte(`{"access_token":"sk-ant-oat01-short","refresh_token":"` + realClaude + `","expires_in":28800}`)
	resp := newResp(req, 200, http.Header{"Content-Type": {"application/json"}}, upstream)
	res, err := m.TransformResponse(context.Background(), tctx(), req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)

	body := readAll(t, resp.Body)
	require.NotContains(t, string(body), realClaude)
	require.Contains(t, string(body), `"access_token":"sk-ant-oat01-short"`, "access token stays real by design")
	require.Contains(t, string(body), `"expires_in":28800`, "numbers must survive re-encoding unchanged")
	requireLengthMatches(t, resp, body)

	var obj map[string]any
	require.NoError(t, json.Unmarshal(body, &obj))
	mask := obj["refresh_token"].(string)
	require.True(t, strings.HasPrefix(mask, "sk-ant-ort01-"))
	require.Len(t, mask, len(realClaude))
	require.True(t, store.IsMask(mask))
}

func TestOAuthRequestSwapsMaskedRefresh(t *testing.T) {
	m, store := newTestTransform(t)
	mask, err := store.Tokenize(realClaude, "claude:refresh", clientIP, "sk-ant-ort01-")
	require.NoError(t, err)

	reqBody := []byte(`{"grant_type":"refresh_token","refresh_token":"` + mask + `","client_id":"abc"}`)
	req := newReq("POST", claudeToken, reqBody)
	req.Header.Set("Content-Length", strconv.Itoa(len(reqBody)))
	_, err = m.TransformRequest(context.Background(), tctx(), req)
	require.NoError(t, err)

	out := readAll(t, req.Body)
	require.Contains(t, string(out), `"refresh_token":"`+realClaude+`"`)
	require.NotContains(t, string(out), mask)
	require.Equal(t, int64(len(out)), req.ContentLength)
	require.Equal(t, strconv.Itoa(len(out)), req.Header.Get("Content-Length"))
}

func TestOAuthPrefixMismatchFailsClosed(t *testing.T) {
	m, _ := newTestTransform(t)
	req := newReq("POST", claudeToken, nil)
	upstream := []byte(`{"refresh_token":"sk-ant-NEWFORMAT-0123456789"}`)
	resp := newResp(req, 200, http.Header{"Content-Type": {"application/json"}}, upstream)

	res, err := m.TransformResponse(context.Background(), tctx(), req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
	require.Equal(t, http.StatusInternalServerError, res.Response.StatusCode)
	require.NotContains(t, string(readAll(t, res.Response.Body)), "NEWFORMAT")
}

func TestOAuthMaskIsNotMaskedAgain(t *testing.T) {
	m, store := newTestTransform(t)
	mask, err := store.Tokenize(realCodex, "codex:refresh", clientIP, "rt.1.")
	require.NoError(t, err)

	req := newReq("POST", "https://auth.openai.com/oauth/token", nil)
	upstream := []byte(`{"refresh_token":"` + mask + `"}`)
	resp := newResp(req, 200, http.Header{"Content-Type": {"application/json"}}, upstream)
	_, err = m.TransformResponse(context.Background(), tctx(), req, resp)
	require.NoError(t, err)
	require.Equal(t, upstream, readAll(t, resp.Body))
}

func TestOAuthNonJSONResponsePassesThrough(t *testing.T) {
	m, _ := newTestTransform(t)
	req := newReq("POST", claudeToken, nil)
	upstream := []byte("<html>rate limited</html>")
	resp := newResp(req, 429, http.Header{"Content-Type": {"text/html"}}, upstream)

	res, err := m.TransformResponse(context.Background(), tctx(), req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, upstream, readAll(t, resp.Body))
}

// proxy.max_response_body_bytes truncates silently, so a token response can
// arrive cut off after the real refresh token. A JSON body that does not
// parse must fail closed; a body that is not JSON at all still passes.
func TestOAuthUnparsableJSONFailsClosed(t *testing.T) {
	full := `{"access_token":"sk-ant-oat01-short","refresh_token":"` + realClaude + `","expires_in":28800}`
	truncated := full[:strings.Index(full, realClaude)+len(realClaude)]

	tests := []struct {
		name       string
		ctype      string
		body       string
		wantReject bool
	}{
		{name: "truncated with json content type", ctype: "application/json", body: truncated, wantReject: true},
		{name: "truncated with no content type", ctype: "", body: truncated, wantReject: true},
		{name: "truncated before the token", ctype: "application/json", body: `{"access_tok`, wantReject: true},
		{name: "empty json body", ctype: "application/json", body: "", wantReject: false},
		{name: "html error page", ctype: "text/html", body: "<html>bad gateway</html>", wantReject: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := newTestTransform(t)
			req := newReq("POST", claudeToken, nil)
			header := http.Header{}
			if tc.ctype != "" {
				header.Set("Content-Type", tc.ctype)
			}
			resp := newResp(req, 200, header, []byte(tc.body))

			res, err := m.TransformResponse(context.Background(), tctx(), req, resp)
			require.NoError(t, err)

			if tc.wantReject {
				require.Equal(t, transform.ActionReject, res.Action)
				require.Equal(t, http.StatusInternalServerError, res.Response.StatusCode)
				require.NotContains(t, string(readAll(t, res.Response.Body)), realClaude)
				return
			}
			require.Equal(t, transform.ActionContinue, res.Action)
			require.Equal(t, tc.body, string(readAll(t, resp.Body)))
		})
	}
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

func TestFactoryRequiresStoreDir(t *testing.T) {
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte("github: {consume_rules: [{host: github.com}], issue_rules: [{host: github.com}]}"), &node))
	_, err := factory(*node.Content[0], slog.Default())
	require.ErrorContains(t, err, "store_dir is required")
}

func TestFactoryFailsLoudWithoutMasterKey(t *testing.T) {
	var node yaml.Node
	cfg := "store_dir: " + t.TempDir() + "\ngithub: {consume_rules: [{host: github.com}], issue_rules: [{host: github.com}]}"
	require.NoError(t, yaml.Unmarshal([]byte(cfg), &node))
	_, err := factory(*node.Content[0], slog.Default())
	require.ErrorIs(t, err, ErrStore)
}

func TestFactoryBuildsFromYAML(t *testing.T) {
	var node yaml.Node
	cfg := `
store_dir: ` + newStoreDir(t) + `
github:
  consume_rules: [{host: github.com}, {host: api.github.com}]
  issue_rules: [{host: github.com, methods: [POST], paths: [/login/oauth/access_token]}]
oauth_refresh:
  - kind: "claude:refresh"
    mask_prefix: "sk-ant-ort01-"
    rules: [{host: platform.claude.com, methods: [POST], paths: [/v1/oauth/token]}]
`
	require.NoError(t, yaml.Unmarshal([]byte(cfg), &node))
	tr, err := factory(*node.Content[0], slog.Default())
	require.NoError(t, err)
	require.Equal(t, "credential_mask", tr.Name())
}
