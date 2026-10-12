package credmask

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
)

// credential_mask swaps real credentials in only inside TLS: its swap rules
// are compiled with require_tls forced on. Masking still runs on plain HTTP.
//
// httptest.NewRequest (via newReq) sets req.TLS for https:// targets only, so
// an http:// target is exactly what the proxy sees for a plain-HTTP request.
// The https:// counterparts of these swaps are covered in credmask_test.go.

func TestTLS_GitHubTokenIsNotSwappedOnPlainHTTP(t *testing.T) {
	m, store := newTestTransform(t)
	mask, err := store.Tokenize(realGitHub, "github:access_token", clientIP, "")
	require.NoError(t, err)

	for _, scheme := range []string{"token", "Bearer"} {
		req := newReq("GET", "http://api.github.com/user", nil)
		require.Nil(t, req.TLS)
		req.Header.Set("Authorization", scheme+" "+mask)
		_, err := m.TransformRequest(context.Background(), tctx(), req)
		require.NoError(t, err)
		require.Equal(t, scheme+" "+mask, req.Header.Get("Authorization"), "mask must stay in place on plain HTTP")
	}
}

func TestTLS_GitHubBasicAuthIsNotSwappedOnPlainHTTP(t *testing.T) {
	m, store := newTestTransform(t)
	mask, err := store.Tokenize(realGitHub, "github:access_token", clientIP, "")
	require.NoError(t, err)

	maskedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+mask))
	req := newReq("POST", "http://github.com/org/repo.git/git-receive-pack", nil)
	req.Header.Set("Authorization", maskedAuth)
	_, err = m.TransformRequest(context.Background(), tctx(), req)
	require.NoError(t, err)
	require.Equal(t, maskedAuth, req.Header.Get("Authorization"))
}

func TestTLS_OAuthRefreshIsNotSwappedOnPlainHTTP(t *testing.T) {
	m, store := newTestTransform(t)
	mask, err := store.Tokenize(realClaude, "claude:refresh", clientIP, "sk-ant-ort01-")
	require.NoError(t, err)

	reqBody := []byte(`{"grant_type":"refresh_token","refresh_token":"` + mask + `","client_id":"abc"}`)
	req := newReq("POST", "http://platform.claude.com/v1/oauth/token", reqBody)
	_, err = m.TransformRequest(context.Background(), tctx(), req)
	require.NoError(t, err)

	out := readAll(t, req.Body)
	require.Equal(t, reqBody, out, "body must be untouched on plain HTTP")
}

// The guard is not configurable: a config that says require_tls: false on a
// swap rule still gets it forced on.
func TestTLS_ConfigCannotTurnOffTheSwapGuard(t *testing.T) {
	store := newTestStore(t)
	c := config{
		StoreDir: "unused-in-tests",
		GitHub: &githubConfig{
			ConsumeRules: []hostmatch.RuleConfig{{Host: "api.github.com", RequireTLS: false}},
			IssueRules:   []hostmatch.RuleConfig{{Host: "github.com", Methods: []string{"POST"}, Paths: []string{"/login/oauth/access_token"}}},
		},
		OAuthRefresh: []oauthRefreshConfig{
			{Kind: "claude:refresh", MaskPrefix: "sk-ant-ort01-", Rules: []hostmatch.RuleConfig{{Host: "platform.claude.com", RequireTLS: false}}},
		},
	}
	m, err := newFromConfig(c, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	for _, r := range m.githubConsume {
		require.True(t, r.RequireTLS, "github consume rules must require TLS")
	}
	for _, r := range m.oauth[0].swapRules {
		require.True(t, r.RequireTLS, "oauth swap rules must require TLS")
	}
	for _, r := range m.oauth[0].rules {
		require.False(t, r.RequireTLS, "oauth masking rules keep the configured value")
	}
}

// Masking is the safe direction, so it still runs on plain HTTP: a real
// token arriving in clear text is still kept off the client.
func TestTLS_GitHubIssuanceIsStillMaskedOnPlainHTTP(t *testing.T) {
	m, _ := newTestTransform(t)
	req := newReq("POST", "http://github.com/login/oauth/access_token", nil)
	resp := newResp(req, 200, http.Header{"Content-Type": {"application/json"}}, []byte(`{"access_token":"`+realGitHub+`"}`))

	_, err := m.TransformResponse(context.Background(), tctx(), req, resp)
	require.NoError(t, err)
	require.NotContains(t, string(readAll(t, resp.Body)), realGitHub)
}

func TestTLS_OAuthRefreshResponseIsStillMaskedOnPlainHTTP(t *testing.T) {
	m, _ := newTestTransform(t)
	req := newReq("POST", "http://platform.claude.com/v1/oauth/token", nil)
	resp := newResp(req, 200, http.Header{"Content-Type": {"application/json"}}, []byte(`{"access_token":"at","refresh_token":"`+realClaude+`"}`))

	_, err := m.TransformResponse(context.Background(), tctx(), req, resp)
	require.NoError(t, err)
	require.NotContains(t, string(readAll(t, resp.Body)), realClaude)
}
