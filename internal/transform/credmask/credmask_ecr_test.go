package credmask

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// ECR: GetAuthorizationToken returns base64("AWS:<token>"); the token is
// masked. The registry gets Basic AWS:<mask>; the mask is swapped back.

const (
	ecrAPI      = "https://api.ecr.af-south-1.amazonaws.com/"
	ecrRegistry = "https://123456789012.dkr.ecr.af-south-1.amazonaws.com"
	// Shaped like a real ECR token: base64 (with + and /), no underscore.
	realECRToken = "eyJwYXlsb2FkIjoiQUJDKy8rZGVmIiwiZGF0YWtleSI6IlhZWi9xcnMrIn0="
)

func newECRTransform(t *testing.T) (*CredMask, *Store) {
	t.Helper()
	store := newTestStore(t)
	c := config{
		StoreDir: "unused-in-tests",
		ECR: &ecrConfig{
			TokenKind:    "ecr:token",
			IssueRules:   []hostmatch.RuleConfig{{Host: "api.ecr.af-south-1.amazonaws.com", Methods: []string{"POST"}}},
			ConsumeRules: []hostmatch.RuleConfig{{Host: "*.dkr.ecr.af-south-1.amazonaws.com"}},
		},
	}
	m, err := newFromConfig(c, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	return m, store
}

func getAuthTokenRequest() *http.Request {
	req := newReq("POST", ecrAPI, []byte("{}"))
	req.Header.Set("X-Amz-Target", "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken")
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	return req
}

func ecrTokenResponseBody(token string) []byte {
	encoded := base64.StdEncoding.EncodeToString([]byte("AWS:" + token))
	return []byte(`{"authorizationData":[{"authorizationToken":"` + encoded + `","expiresAt":1.792384E9,"proxyEndpoint":"` + ecrRegistry + `"}]}`)
}

func basicAWS(password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("AWS:"+password))
}

// maskFromResponse decodes the masked token the client would get.
func maskFromResponse(t *testing.T, body []byte) string {
	t.Helper()
	obj, ok := parseJSONObject(body)
	require.True(t, ok)
	entry := obj["authorizationData"].([]any)[0].(map[string]any)
	decoded, err := base64.StdEncoding.DecodeString(entry["authorizationToken"].(string))
	require.NoError(t, err)
	user, mask, ok := strings.Cut(string(decoded), ":")
	require.True(t, ok)
	require.Equal(t, "AWS", user)
	return mask
}

func TestECR_TokenIsMaskedAndSwappedBack(t *testing.T) {
	m, store := newECRTransform(t)
	ctx := context.Background()

	// 1. GetAuthorizationToken: asked for uncompressed, token masked.
	req := getAuthTokenRequest()
	req.Header.Set("Accept-Encoding", "gzip")
	_, err := m.TransformRequest(ctx, tctx(), req)
	require.NoError(t, err)
	require.Equal(t, "identity", req.Header.Get("Accept-Encoding"))

	resp := newResp(req, 200, http.Header{"Content-Type": {"application/x-amz-json-1.1"}}, ecrTokenResponseBody(realECRToken))
	res, err := m.TransformResponse(ctx, tctx(), req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)

	body := readAll(t, resp.Body)
	require.NotContains(t, string(body), base64.StdEncoding.EncodeToString([]byte("AWS:"+realECRToken)))
	requireLengthMatches(t, resp, body)
	require.Contains(t, string(body), `"expiresAt":1.792384E9`, "other fields kept exactly")
	require.Contains(t, string(body), `"proxyEndpoint":"`+ecrRegistry+`"`)

	mask := maskFromResponse(t, body)
	require.NotEqual(t, realECRToken, mask)
	require.Len(t, mask, len(realECRToken))
	require.True(t, store.IsMask(mask))

	// 2. The registry request carries the mask; it is swapped for the real token.
	push := newReq("PUT", ecrRegistry+"/v2/repo/manifests/latest", nil)
	push.Header.Set("Authorization", basicAWS(mask))
	pushCtx := tctx()
	_, err = m.TransformRequest(ctx, pushCtx, push)
	require.NoError(t, err)
	require.Equal(t, basicAWS(realECRToken), push.Header.Get("Authorization"))
	require.Equal(t, []string{"credential_mask"}, pushCtx.CredentialsInjectedBy())
}

func TestECR_RegistryRequestWithoutOurMaskIsLeftAlone(t *testing.T) {
	m, _ := newECRTransform(t)
	tests := []struct {
		name string
		auth string
	}{
		{"someone else's token", basicAWS("their-own-registry-token")},
		{"bearer", "Bearer abc"},
		{"no auth", ""},
		{"not base64", "Basic !!!"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := newReq("PUT", ecrRegistry+"/v2/repo/manifests/latest", nil)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			c := tctx()
			_, err := m.TransformRequest(context.Background(), c, req)
			require.NoError(t, err)
			require.Equal(t, tc.auth, req.Header.Get("Authorization"))
			require.Empty(t, c.CredentialsInjectedBy(), "nothing swapped, so nothing marked")
		})
	}
}

func TestECR_MaskIsNotSwappedOnPlainHTTP(t *testing.T) {
	m, store := newECRTransform(t)
	mask, err := store.Tokenize(realECRToken, "ecr:token", clientIP, "")
	require.NoError(t, err)

	req := newReq("GET", "http://123456789012.dkr.ecr.af-south-1.amazonaws.com/v2/", nil)
	req.Header.Set("Authorization", basicAWS(mask))
	_, err = m.TransformRequest(context.Background(), tctx(), req)
	require.NoError(t, err)
	require.Equal(t, basicAWS(mask), req.Header.Get("Authorization"))
}

func TestECR_OtherAPICallsAreNotRead(t *testing.T) {
	m, _ := newECRTransform(t)
	req := newReq("POST", ecrAPI, []byte("{}"))
	req.Header.Set("X-Amz-Target", "AmazonEC2ContainerRegistry_V20150921.DescribeRepositories")
	req.Header.Set("Accept-Encoding", "gzip")
	_, err := m.TransformRequest(context.Background(), tctx(), req)
	require.NoError(t, err)
	require.Equal(t, "gzip", req.Header.Get("Accept-Encoding"), "only the token call is asked for uncompressed")

	upstream := []byte("not json at all, and big responses must not abort")
	resp := newResp(req, 200, nil, upstream)
	res, err := m.TransformResponse(context.Background(), tctx(), req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, upstream, readAll(t, resp.Body))
}

func TestECR_UnexpectedTokenResponseFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"truncated JSON", string(ecrTokenResponseBody(realECRToken))[:60]},
		{"no authorizationData", `{"something":"else"}`},
		{"token not base64", `{"authorizationData":[{"authorizationToken":"!!!"}]}`},
		{"token not user:token", `{"authorizationData":[{"authorizationToken":"` + base64.StdEncoding.EncodeToString([]byte("nocolon")) + `"}]}`},
		{"token with underscore", string(ecrTokenResponseBody("abc_defghijklmnop"))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := newECRTransform(t)
			req := getAuthTokenRequest()
			resp := newResp(req, 200, nil, []byte(tc.body))
			res, err := m.TransformResponse(context.Background(), tctx(), req, resp)
			require.NoError(t, err)
			require.Equal(t, transform.ActionReject, res.Action)
			require.Equal(t, http.StatusInternalServerError, res.Response.StatusCode)
		})
	}
}

func TestECR_ErrorResponseIsPassedThrough(t *testing.T) {
	m, _ := newECRTransform(t)
	req := getAuthTokenRequest()
	upstream := []byte(`{"__type":"AccessDeniedException","message":"no"}`)
	resp := newResp(req, 400, nil, upstream)
	res, err := m.TransformResponse(context.Background(), tctx(), req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Equal(t, upstream, readAll(t, resp.Body))
}

func TestECR_ConfigValidation(t *testing.T) {
	ecr := func() *ecrConfig {
		return &ecrConfig{
			TokenKind:    "ecr:token",
			IssueRules:   []hostmatch.RuleConfig{{Host: "api.ecr.af-south-1.amazonaws.com"}},
			ConsumeRules: []hostmatch.RuleConfig{{Host: "*.dkr.ecr.af-south-1.amazonaws.com"}},
		}
	}
	tests := []struct {
		name    string
		mutate  func(c *config)
		wantErr string
	}{
		{"missing kind", func(c *config) { c.ECR.TokenKind = "" }, "ecr.token_kind is required"},
		{"missing issue rules", func(c *config) { c.ECR.IssueRules = nil }, "ecr needs both"},
		{"missing consume rules", func(c *config) { c.ECR.ConsumeRules = nil }, "ecr needs both"},
		{"kind shared with oauth", func(c *config) {
			c.OAuthRefresh = []oauthRefreshConfig{{Kind: "ecr:token", MaskPrefix: "x", Rules: []hostmatch.RuleConfig{{Host: "a.example"}}}}
		}, "already used"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := config{StoreDir: "unused", ECR: ecr()}
			tc.mutate(&c)
			_, err := newFromConfig(c, newTestStore(t), nil)
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}
