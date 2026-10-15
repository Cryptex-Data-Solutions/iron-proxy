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

func TestTLS_MaskIsNotSwappedOnPlainHTTP(t *testing.T) {
	tests := []struct {
		name       string
		real       string
		kind       string
		maskPrefix string
		method     string
		url        string
		authHeader func(mask string) string // nil = no Authorization header
		body       func(mask string) []byte // nil = no body
	}{
		{
			name:       "github token scheme",
			real:       realGitHub,
			kind:       "github:access_token",
			method:     "GET",
			url:        "http://api.github.com/user",
			authHeader: func(mask string) string { return "token " + mask },
		},
		{
			name:       "github bearer scheme",
			real:       realGitHub,
			kind:       "github:access_token",
			method:     "GET",
			url:        "http://api.github.com/user",
			authHeader: func(mask string) string { return "Bearer " + mask },
		},
		{
			name:   "github basic auth on git push",
			real:   realGitHub,
			kind:   "github:access_token",
			method: "POST",
			url:    "http://github.com/org/repo.git/git-receive-pack",
			authHeader: func(mask string) string {
				return "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+mask))
			},
		},
		{
			name:       "oauth refresh token in body",
			real:       realClaude,
			kind:       "claude:refresh",
			maskPrefix: "sk-ant-ort01-",
			method:     "POST",
			url:        "http://platform.claude.com/v1/oauth/token",
			body: func(mask string) []byte {
				return []byte(`{"grant_type":"refresh_token","refresh_token":"` + mask + `","client_id":"abc"}`)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, store := newTestTransform(t)
			mask, err := store.Tokenize(tc.real, tc.kind, clientIP, tc.maskPrefix)
			require.NoError(t, err)

			var reqBody []byte
			if tc.body != nil {
				reqBody = tc.body(mask)
			}
			req := newReq(tc.method, tc.url, reqBody)
			require.Nil(t, req.TLS)
			var wantAuth string
			if tc.authHeader != nil {
				wantAuth = tc.authHeader(mask)
				req.Header.Set("Authorization", wantAuth)
			}

			_, err = m.TransformRequest(context.Background(), tctx(), req)
			require.NoError(t, err)

			require.Equal(t, wantAuth, req.Header.Get("Authorization"), "mask must stay in place on plain HTTP")
			if reqBody != nil {
				require.Equal(t, reqBody, readAll(t, req.Body), "body must be untouched on plain HTTP")
			}
		})
	}
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
	for _, r := range m.githubRefresh {
		require.True(t, r.RequireTLS, "github refresh swap rules must require TLS")
	}
	for _, r := range m.githubIssue {
		require.False(t, r.RequireTLS, "github issuance masking rules keep the configured value")
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
func TestTLS_ResponseIsStillMaskedOnPlainHTTP(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		respBody string
		real     string
	}{
		{
			name:     "github issuance",
			url:      "http://github.com/login/oauth/access_token",
			respBody: `{"access_token":"` + realGitHub + `"}`,
			real:     realGitHub,
		},
		{
			name:     "oauth refresh response",
			url:      "http://platform.claude.com/v1/oauth/token",
			respBody: `{"access_token":"at","refresh_token":"` + realClaude + `"}`,
			real:     realClaude,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := newTestTransform(t)
			req := newReq("POST", tc.url, nil)
			resp := newResp(req, 200, http.Header{"Content-Type": {"application/json"}}, []byte(tc.respBody))

			_, err := m.TransformResponse(context.Background(), tctx(), req, resp)
			require.NoError(t, err)
			require.NotContains(t, string(readAll(t, resp.Body)), tc.real)
		})
	}
}
