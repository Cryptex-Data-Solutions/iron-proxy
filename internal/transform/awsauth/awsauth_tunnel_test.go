package awsauth

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// A connection the proxy does not decrypt (sni-only, or a host left out of
// tls.intercept) reaches aws_auth as a host-only stand-in request: no method,
// no headers. It must pass, or no AWS host could be tunnelled. The same
// request under MITM is still rejected for having no signature.
func TestTransformRequest_TunnelledConnectionPasses(t *testing.T) {
	srcs := map[string]secrets.Source{
		"AWS_ACCESS_KEY_ID":     &staticSource{name: "access", value: "AKIA"},
		"AWS_SECRET_ACCESS_KEY": &staticSource{name: "secret", value: "shh"},
	}
	a := buildTransformWith(t, minimalYAML, mapBuilder(srcs))

	standIn := func() *http.Request {
		host := "ssm.af-south-1.amazonaws.com"
		req := &http.Request{Host: host, URL: &url.URL{Scheme: "https", Host: host}, Header: http.Header{}}
		req.Body = transform.NewBufferedBody(http.NoBody, 0)
		return req
	}

	tunnelled := &transform.TransformContext{Mode: transform.ModeSNIOnly}
	res, err := a.TransformRequest(context.Background(), tunnelled, standIn())
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)

	res, err = a.TransformRequest(context.Background(), newContext(), standIn())
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action, "under MITM an unsigned request is still rejected")
}
