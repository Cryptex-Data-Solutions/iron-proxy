package awsauth

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
)

// The "secrets" transform is registered because awsauth.go imports its
// package (for secret sources).
//
// End to end through a real pipeline, no hand-set flag: a write to an
// AWS-hosted API (here an API Gateway taking an API key) passes the write
// policy only because the secrets transform swapped in a credential the
// proxy holds. The same write without the swap is rejected.
func TestWritePolicy_PipelineWithSecretsSwap(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", realKeyID)
	t.Setenv("AWS_SECRET_ACCESS_KEY", "real-secret")
	t.Setenv("GATEWAY_API_KEY", "real-gateway-key")

	build := func(name, cfg string) transform.Transformer {
		t.Helper()
		factory, err := transform.Lookup(name)
		require.NoError(t, err)
		tr, err := factory(yamlFromString(t, cfg), slog.Default())
		require.NoError(t, err)
		return tr
	}
	secretsTr := build("secrets", `
secrets:
  - source: {type: env, var: GATEWAY_API_KEY}
    rules: [{host: "*.execute-api.us-east-1.amazonaws.com"}]
    replace:
      proxy_value: "proxy-gateway-key"
      match_headers: ["X-Api-Key"]
`)
	awsTr := build("aws_auth", writePolicyYAML)
	pipeline := transform.NewPipeline([]transform.Transformer{secretsTr, awsTr}, transform.BodyLimits{}, slog.Default())

	post := func(apiKey string) (*http.Request, *http.Response) {
		req := plainRequest(t, "POST", "https://abc123.execute-api.us-east-1.amazonaws.com/orders", "")
		req.Header.Set("X-Api-Key", apiKey)
		var traces []transform.TransformTrace
		rejected, err := pipeline.ProcessRequest(context.Background(), newContext(), req, &traces)
		require.NoError(t, err)
		return req, rejected
	}

	req, rejected := post("proxy-gateway-key")
	require.Nil(t, rejected, "the secrets swap marks the request, so the write passes")
	require.Equal(t, "real-gateway-key", req.Header.Get("X-Api-Key"))

	_, rejected = post("the-clients-own-key")
	require.NotNil(t, rejected, "nothing was swapped, so the write is blocked")
	require.Equal(t, http.StatusForbidden, rejected.StatusCode)
}

// A secrets body swap that shortens the body, followed by aws_auth in a
// mode that signs without reading the body: the swap keeps ContentLength in
// step, so aws_auth must not mistake the rewrite for a truncated body.
func TestDeclaredPayload_PipelineAfterShorterSecretsBodySwap(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", realKeyID)
	t.Setenv("AWS_SECRET_ACCESS_KEY", "real-secret")
	t.Setenv("UPLOAD_TOKEN", "short") // shorter than the placeholder

	build := func(name, cfg string) transform.Transformer {
		t.Helper()
		factory, err := transform.Lookup(name)
		require.NoError(t, err)
		tr, err := factory(yamlFromString(t, cfg), slog.Default())
		require.NoError(t, err)
		return tr
	}
	secretsTr := build("secrets", `
secrets:
  - source: {type: env, var: UPLOAD_TOKEN}
    rules: [{host: "*.s3.af-south-1.amazonaws.com"}]
    replace:
      proxy_value: "proxy-upload-token"
      match_body: true
`)
	awsTr := build("aws_auth", minimalYAML)
	pipeline := transform.NewPipeline([]transform.Transformer{secretsTr, awsTr}, transform.BodyLimits{}, slog.Default())

	tests := []struct {
		name     string
		declared string
	}{
		{name: "client declares UNSIGNED-PAYLOAD", declared: "UNSIGNED-PAYLOAD"},
		{name: "client declares a hex hash (hashed by the proxy)", declared: ""}, // set below
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"token":"proxy-upload-token","data":"x"}`
			req, err := http.NewRequest(http.MethodPut, "https://bucket.s3.af-south-1.amazonaws.com/key", nil)
			require.NoError(t, err)
			req.Body = transform.NewBufferedBody(io.NopCloser(strings.NewReader(body)), 1<<20)
			req.ContentLength = int64(len(body))
			req.Header.Set("Authorization", placeholderAuth)
			declared := tt.declared
			if declared == "" {
				declared = sha256Hex([]byte(body))
			}
			req.Header.Set("X-Amz-Content-Sha256", declared)

			var traces []transform.TransformTrace
			rejected, err := pipeline.ProcessRequest(context.Background(), newContext(), req, &traces)
			require.NoError(t, err)
			require.Nil(t, rejected, "a shorter body from the swap is not a truncated body")

			want := `{"token":"short","data":"x"}`
			require.Equal(t, int64(len(want)), req.ContentLength)
			require.Contains(t, req.Header.Get("Authorization"), "Credential="+realKeyID+"/")
			sent, err := io.ReadAll(transform.RequireBufferedBody(req.Body).StreamingReader())
			require.NoError(t, err)
			require.Equal(t, want, string(sent))
		})
	}
}

// A body cut off at the buffer limit, then made longer by a secrets swap,
// can end up as long as its original Content-Length. aws_auth must still
// refuse it on the paths that sign without reading the body: the truncation
// is carried over by the swap, not inferred from the length.
func TestDeclaredPayload_PipelineRefusesExpandedTruncatedBody(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", realKeyID)
	t.Setenv("AWS_SECRET_ACCESS_KEY", "real-secret")
	t.Setenv("UPLOAD_TOKEN", strings.Repeat("R", 100)) // much longer than the placeholder

	build := func(name, cfg string) transform.Transformer {
		t.Helper()
		factory, err := transform.Lookup(name)
		require.NoError(t, err)
		tr, err := factory(yamlFromString(t, cfg), slog.Default())
		require.NoError(t, err)
		return tr
	}
	secretsTr := build("secrets", `
secrets:
  - source: {type: env, var: UPLOAD_TOKEN}
    rules: [{host: "*.s3.af-south-1.amazonaws.com"}]
    replace:
      proxy_value: "proxy-upload-token"
      match_body: true
`)
	awsTr := build("aws_auth", minimalYAML)
	pipeline := transform.NewPipeline([]transform.Transformer{secretsTr, awsTr}, transform.BodyLimits{}, slog.Default())

	prefix := `{"token":"proxy-upload-token"}`
	body := prefix + strings.Repeat(" ", 64) // the padding is cut off by the limit
	req, err := http.NewRequest(http.MethodPut, "https://bucket.s3.af-south-1.amazonaws.com/key", nil)
	require.NoError(t, err)
	req.Body = transform.NewBufferedBody(io.NopCloser(strings.NewReader(body)), int64(len(prefix)))
	req.ContentLength = int64(len(body))
	req.Header.Set("Authorization", placeholderAuth)
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")

	var traces []transform.TransformTrace
	rejected, err := pipeline.ProcessRequest(context.Background(), newContext(), req, &traces)
	require.NoError(t, err)

	// The scenario is real: the rewrite is at least as long as the original.
	require.GreaterOrEqual(t, transform.RequireBufferedBody(req.Body).Len(), len(body))
	require.NotNil(t, rejected, "a truncated body must not be signed, however long the rewrite")
	require.Equal(t, http.StatusRequestEntityTooLarge, rejected.StatusCode)
}
