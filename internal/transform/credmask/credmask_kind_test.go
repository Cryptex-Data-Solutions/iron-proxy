package credmask

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
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
