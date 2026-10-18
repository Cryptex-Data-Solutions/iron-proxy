package credmask

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
)

// A mask resolves only as the kind it was minted as, so one provider's
// credential is never swapped into a request to another provider.

func TestKind_StoreResolvesOnlyTheMintedKind(t *testing.T) {
	tests := []struct {
		name     string
		minted   string
		resolved string
		wantOK   bool
	}{
		{name: "same kind resolves", minted: "github:access_token", resolved: "github:access_token", wantOK: true},
		{name: "github refresh token as access token", minted: "github:refresh_token", resolved: "github:access_token", wantOK: false},
		{name: "claude refresh as github access token", minted: "claude:refresh", resolved: "github:access_token", wantOK: false},
		{name: "claude refresh as codex refresh", minted: "claude:refresh", resolved: "codex:refresh", wantOK: false},
		{name: "empty expected kind never resolves", minted: "github:access_token", resolved: "", wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			mask, err := s.Tokenize(realGitHub, tc.minted, clientIP, "")
			require.NoError(t, err)

			real, ok, err := s.Resolve(mask, tc.resolved, clientIP, true)
			require.NoError(t, err)
			require.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				require.Equal(t, realGitHub, real)
			} else {
				require.Empty(t, real)
			}
		})
	}
}

// Reuse is per kind: the same secret and client tokenized under a second
// kind (say, after an oauth_refresh kind is renamed) gets its own mask, and
// each mask resolves as its own kind. Tokenizing again under the same kind
// still returns the existing mask.
func TestKind_ReuseIsPerKind(t *testing.T) {
	s := newTestStore(t)
	first, err := s.Tokenize(realClaude, "claude:refresh", clientIP, "sk-ant-ort01-")
	require.NoError(t, err)
	again, err := s.Tokenize(realClaude, "claude:refresh", clientIP, "sk-ant-ort01-")
	require.NoError(t, err)
	require.Equal(t, first, again, "same kind reuses the mask")

	renamed, err := s.Tokenize(realClaude, "anthropic:refresh", clientIP, "sk-ant-ort01-")
	require.NoError(t, err)
	require.NotEqual(t, first, renamed, "a second kind gets its own mask")

	for mask, kind := range map[string]string{first: "claude:refresh", renamed: "anthropic:refresh"} {
		real, ok, err := s.Resolve(mask, kind, clientIP, true)
		require.NoError(t, err)
		require.True(t, ok, kind)
		require.Equal(t, realClaude, real)
	}
}

// Every kind comes from config, GitHub's included, and every kind in the
// config must be unique, or the kind check cannot tell providers apart.
func TestKind_ConfigRejectsDuplicateKinds(t *testing.T) {
	claude := oauthRefreshConfig{Kind: "claude:refresh", MaskPrefix: "sk-ant-ort01-", Rules: []hostmatch.RuleConfig{{Host: "platform.claude.com"}}}
	codex := oauthRefreshConfig{Kind: "codex:refresh", MaskPrefix: "rt.1.", Rules: []hostmatch.RuleConfig{{Host: "auth.openai.com"}}}
	withKind := func(p oauthRefreshConfig, kind string) oauthRefreshConfig { p.Kind = kind; return p }
	github := func(access, refresh string) *githubConfig {
		return &githubConfig{
			AccessTokenKind:  access,
			RefreshTokenKind: refresh,
			ConsumeRules:     []hostmatch.RuleConfig{{Host: "api.github.com"}},
			IssueRules:       []hostmatch.RuleConfig{{Host: "github.com"}},
		}
	}

	tests := []struct {
		name    string
		github  *githubConfig
		entries []oauthRefreshConfig
		wantErr string // "" = config loads
	}{
		{name: "distinct kinds load", github: github("github:access_token", "github:refresh_token"), entries: []oauthRefreshConfig{claude, codex}},
		{name: "two oauth providers sharing a kind", entries: []oauthRefreshConfig{withKind(claude, "refresh"), withKind(codex, "refresh")}, wantErr: `kind "refresh" is already used by oauth_refresh[0].kind`},
		{name: "oauth provider reusing github's access kind", github: github("github:access_token", "github:refresh_token"), entries: []oauthRefreshConfig{withKind(claude, "github:access_token")}, wantErr: "already used by github.access_token_kind"},
		{name: "oauth provider reusing github's refresh kind", github: github("github:access_token", "github:refresh_token"), entries: []oauthRefreshConfig{withKind(claude, "github:refresh_token")}, wantErr: "already used by github.refresh_token_kind"},
		{name: "github access and refresh sharing a kind", github: github("github", "github"), wantErr: "already used by github.access_token_kind"},
		{name: "github access kind is required", github: github("", "github:refresh_token"), wantErr: "github.access_token_kind is required"},
		{name: "github refresh kind is required", github: github("github:access_token", ""), wantErr: "github.refresh_token_kind is required"},
		{name: "oauth kind is required", entries: []oauthRefreshConfig{withKind(claude, "")}, wantErr: "oauth_refresh[0].kind is required"},
		{name: "names are free-form", github: github("gh-access", "gh-refresh"), entries: []oauthRefreshConfig{withKind(claude, "github:access_token")}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := config{StoreDir: "unused-in-tests", GitHub: tc.github, OAuthRefresh: tc.entries}
			_, err := newFromConfig(c, newTestStore(t), slog.New(slog.NewTextHandler(io.Discard, nil)))
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// The GitHub kinds are whatever the config names them: a login is masked
// under the configured names, and a later request swaps using them.
func TestKind_GitHubUsesTheConfiguredKinds(t *testing.T) {
	store := newTestStore(t)
	c := config{
		StoreDir: "unused-in-tests",
		GitHub: &githubConfig{
			AccessTokenKind:  "gh-access",
			RefreshTokenKind: "gh-refresh",
			ConsumeRules:     []hostmatch.RuleConfig{{Host: "api.github.com"}},
			IssueRules:       []hostmatch.RuleConfig{{Host: "github.com", Methods: []string{"POST"}, Paths: []string{"/login/oauth/access_token"}}},
		},
	}
	m, err := newFromConfig(c, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	// Login: both tokens are masked under the configured kinds.
	req := newReq("POST", issuePath, nil)
	upstream := []byte(`{"access_token":"` + realGitHub + `","refresh_token":"` + realGitHubRefresh + `"}`)
	resp := newResp(req, 200, http.Header{"Content-Type": {"application/json"}}, upstream)
	_, err = m.TransformResponse(context.Background(), tctx(), req, resp)
	require.NoError(t, err)
	var obj map[string]string
	require.NoError(t, json.Unmarshal(readAll(t, resp.Body), &obj))

	_, ok, err := store.Resolve(obj["access_token"], "gh-access", clientIP, true)
	require.NoError(t, err)
	require.True(t, ok, "access token masked as gh-access")
	_, ok, err = store.Resolve(obj["refresh_token"], "gh-refresh", clientIP, true)
	require.NoError(t, err)
	require.True(t, ok, "refresh token masked as gh-refresh")

	// Use: the access mask swaps in the Authorization header.
	api := newReq("GET", githubAPI, nil)
	api.Header.Set("Authorization", "token "+obj["access_token"])
	_, err = m.TransformRequest(context.Background(), tctx(), api)
	require.NoError(t, err)
	require.Equal(t, "token "+realGitHub, api.Header.Get("Authorization"))
}

func TestKind_RequestSwapsOnlyTheMatchingKind(t *testing.T) {
	tests := []struct {
		name        string
		real        string
		kind        string
		maskPrefix  string
		url         string
		inAuthBody  bool // true: mask goes in the refresh_token body field; false: Authorization header
		wantSwapped bool
	}{
		{name: "github access token in authorization", real: realGitHub, kind: "github:access_token", url: githubAPI, wantSwapped: true},
		{name: "github refresh token in authorization", real: realGitHub, kind: "github:refresh_token", url: githubAPI, wantSwapped: false},
		{name: "claude refresh in github authorization", real: realClaude, kind: "claude:refresh", maskPrefix: "sk-ant-ort01-", url: githubAPI, wantSwapped: false},
		{name: "claude refresh in claude refresh body", real: realClaude, kind: "claude:refresh", maskPrefix: "sk-ant-ort01-", url: claudeToken, inAuthBody: true, wantSwapped: true},
		{name: "claude refresh in codex refresh body", real: realClaude, kind: "claude:refresh", maskPrefix: "sk-ant-ort01-", url: "https://auth.openai.com/oauth/token", inAuthBody: true, wantSwapped: false},
		{name: "codex refresh in claude refresh body", real: realCodex, kind: "codex:refresh", maskPrefix: "rt.1.", url: claudeToken, inAuthBody: true, wantSwapped: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, store := newTestTransform(t)
			mask, err := store.Tokenize(tc.real, tc.kind, clientIP, tc.maskPrefix)
			require.NoError(t, err)

			if tc.inAuthBody {
				req := newReq("POST", tc.url, []byte(`{"grant_type":"refresh_token","refresh_token":"`+mask+`"}`))
				_, err = m.TransformRequest(context.Background(), tctx(), req)
				require.NoError(t, err)
				body := string(readAll(t, req.Body))
				if tc.wantSwapped {
					require.Contains(t, body, tc.real)
				} else {
					require.NotContains(t, body, tc.real)
					require.Contains(t, body, mask)
				}
				return
			}

			req := newReq("GET", tc.url, nil)
			req.Header.Set("Authorization", "Bearer "+mask)
			_, err = m.TransformRequest(context.Background(), tctx(), req)
			require.NoError(t, err)
			if tc.wantSwapped {
				require.Equal(t, "Bearer "+tc.real, req.Header.Get("Authorization"))
			} else {
				require.Equal(t, "Bearer "+mask, req.Header.Get("Authorization"))
			}
		})
	}
}
