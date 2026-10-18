package credmask

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// The refresh swaps read the request body. These tests cover how that body
// is read: which encodings count as plain bytes.

// "identity" is the no-op encoding: the body is plain bytes and the mask must
// still be swapped. A compressed body is left alone.
func TestRequestBody_EncodingIdentityIsPlain(t *testing.T) {
	tests := []struct {
		name        string
		provider    string // "oauth" or "github"
		encoding    string // Content-Encoding header; "" = not set
		wantSwapped bool
	}{
		{name: "oauth no encoding", provider: "oauth", encoding: "", wantSwapped: true},
		{name: "oauth identity", provider: "oauth", encoding: "identity", wantSwapped: true},
		{name: "oauth identity upper case", provider: "oauth", encoding: " IDENTITY ", wantSwapped: true},
		{name: "oauth gzip is left alone", provider: "oauth", encoding: "gzip", wantSwapped: false},
		{name: "github refresh identity", provider: "github", encoding: "identity", wantSwapped: true},
		{name: "github refresh gzip is left alone", provider: "github", encoding: "gzip", wantSwapped: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, store := newTestTransform(t)

			var real, mask, target string
			var body []byte
			var err error
			switch tc.provider {
			case "oauth":
				real = realClaude
				mask, err = store.Tokenize(real, "claude:refresh", clientIP, "sk-ant-ort01-")
				require.NoError(t, err)
				target = claudeToken
				body = []byte(`{"grant_type":"refresh_token","refresh_token":"` + mask + `"}`)
			case "github":
				real = realGitHubRefresh
				mask, err = store.Tokenize(real, githubRefreshKind, clientIP, "")
				require.NoError(t, err)
				target = issuePath
				body = []byte(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {mask}}.Encode())
			}

			req := newReq("POST", target, body)
			if tc.provider == "github" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			if tc.encoding != "" {
				req.Header.Set("Content-Encoding", tc.encoding)
			}

			_, err = m.TransformRequest(context.Background(), tctx(), req)
			require.NoError(t, err)

			sent := string(readAll(t, req.Body))
			if tc.wantSwapped {
				require.Contains(t, sent, real)
				require.NotContains(t, sent, mask)
			} else {
				require.Contains(t, sent, mask)
				require.NotContains(t, sent, real)
			}
		})
	}
}
