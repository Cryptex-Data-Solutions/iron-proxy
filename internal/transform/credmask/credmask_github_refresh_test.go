package credmask

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

const realGitHubRefresh = "ghr_REALrefreshTOKEN0123456789abcdefghijklmnopqrstuv"

// A GitHub refresh token is masked at issuance; a refresh request to the
// issuance endpoint must get the real one back, or expiring GitHub App user
// tokens could never be refreshed through the proxy.
func TestGitHubRefreshSwap(t *testing.T) {
	const refreshURL = "https://github.com/login/oauth/access_token"
	const plainRefreshURL = "http://github.com/login/oauth/access_token"

	tests := []struct {
		name        string
		mintKind    string // kind the mask was minted as
		url         string
		place       string // "query", "form" or "json"
		remoteAddr  string // "" = the client the mask was minted for
		wantSwapped bool
	}{
		{name: "query over TLS", mintKind: "github:refresh_token", url: refreshURL, place: "query", wantSwapped: true},
		{name: "form body over TLS", mintKind: "github:refresh_token", url: refreshURL, place: "form", wantSwapped: true},
		{name: "json body over TLS", mintKind: "github:refresh_token", url: refreshURL, place: "json", wantSwapped: true},
		{name: "query on plain HTTP", mintKind: "github:refresh_token", url: plainRefreshURL, place: "query", wantSwapped: false},
		{name: "form body on plain HTTP", mintKind: "github:refresh_token", url: plainRefreshURL, place: "form", wantSwapped: false},
		{name: "access token mask in refresh_token", mintKind: "github:access_token", url: refreshURL, place: "form", wantSwapped: false},
		{name: "mask from another client", mintKind: "github:refresh_token", url: refreshURL, place: "form", remoteAddr: "10.9.9.9:4000", wantSwapped: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, store := newTestTransform(t)
			mask, err := store.Tokenize(realGitHubRefresh, tc.mintKind, clientIP, "")
			require.NoError(t, err)

			target := tc.url
			var body []byte
			contentType := ""
			switch tc.place {
			case "query":
				target += "?" + url.Values{"grant_type": {"refresh_token"}, "refresh_token": {mask}}.Encode()
			case "form":
				body = []byte(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {mask}}.Encode())
				contentType = "application/x-www-form-urlencoded"
			case "json":
				body = []byte(`{"grant_type":"refresh_token","refresh_token":"` + mask + `"}`)
				contentType = "application/json"
			}

			req := newReq("POST", target, body)
			if contentType != "" {
				req.Header.Set("Content-Type", contentType)
			}
			if tc.remoteAddr != "" {
				req.RemoteAddr = tc.remoteAddr
			}

			_, err = m.TransformRequest(context.Background(), tctx(), req)
			require.NoError(t, err)

			var sent string
			if tc.place == "query" {
				sent = req.URL.RawQuery
			} else {
				sent = string(readAll(t, req.Body))
			}
			if tc.wantSwapped {
				require.Contains(t, sent, realGitHubRefresh)
				require.NotContains(t, sent, mask)
			} else {
				require.NotContains(t, sent, realGitHubRefresh)
				require.Contains(t, sent, mask)
			}
		})
	}
}
