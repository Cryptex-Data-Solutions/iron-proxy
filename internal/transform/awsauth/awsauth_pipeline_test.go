package awsauth

import (
	"context"
	"log/slog"
	"net/http"
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
