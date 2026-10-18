package credmask

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
)

// The refresh swaps read the request body. These tests cover how that body
// is read: which encodings count as plain bytes, which bodies are never read,
// and what happens when the client's body fails mid-read.

// failingReader returns some bytes, then an I/O error, like a client that
// drops the connection mid-upload.
type failingReader struct{ sent bool }

func (f *failingReader) Read(p []byte) (int, error) {
	if !f.sent {
		f.sent = true
		return copy(p, `{"grant_type":"refresh_token","refresh_tok`), nil
	}
	return 0, errors.New("connection reset by peer")
}

// A body declared larger than refreshRequestMaxBytes is never read, so the
// pipeline cannot truncate it; the request goes on untouched. The Codex rule
// matches every POST to auth.openai.com, so this covers unrelated uploads.
func TestRequestBody_OversizedDeclaredBodyIsNotRead(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{name: "oauth host, any POST", target: "https://auth.openai.com/some/upload"},
		{name: "github refresh endpoint", target: issuePath},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := newTestTransform(t)
			req := newReq("POST", tc.target, []byte(`{"refresh_token":"x"}`))
			req.ContentLength = refreshRequestMaxBytes + 1

			res, err := m.TransformRequest(context.Background(), tctx(), req)
			require.NoError(t, err)
			require.Equal(t, transform.ActionContinue, res.Action)
			require.Equal(t, -1, transform.RequireBufferedBody(req.Body).Len(), "body must not be read")
		})
	}
}

// A body that fails mid-read must fail the request (the pipeline answers
// 502), not go upstream with the part that arrived.
func TestRequestBody_ReadErrorFailsTheRequest(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{name: "oauth refresh", target: claudeToken},
		{name: "github refresh", target: issuePath},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := newTestTransform(t)
			req := httptest.NewRequest("POST", tc.target, nil)
			req.RemoteAddr = clientAddr
			req.ContentLength = -1
			req.Body = transform.NewBufferedBody(io.NopCloser(&failingReader{}), 0)

			_, err := m.TransformRequest(context.Background(), tctx(), req)
			require.ErrorContains(t, err, "connection reset by peer")
		})
	}
}

// A body within the limit is still read and swapped (the limit is not off
// by one at the boundary).
func TestRequestBody_BodyAtTheLimitIsSwapped(t *testing.T) {
	m, store := newTestTransform(t)
	mask, err := store.Tokenize(realClaude, "claude:refresh", clientIP, "sk-ant-ort01-")
	require.NoError(t, err)

	body := []byte(`{"grant_type":"refresh_token","refresh_token":"` + mask + `"}`)
	body = append(body, bytes.Repeat([]byte(" "), refreshRequestMaxBytes-len(body))...)
	req := newReq("POST", claudeToken, body)
	require.Equal(t, int64(refreshRequestMaxBytes), req.ContentLength)

	_, err = m.TransformRequest(context.Background(), tctx(), req)
	require.NoError(t, err)
	require.Contains(t, string(readAll(t, req.Body)), realClaude)
}

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
