package grpc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v3"

	transformv1 "github.com/ironsh/iron-proxy/gen/transform/v1"
	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// fakeServer implements TransformServiceServer for testing.
type fakeServer struct {
	transformv1.UnimplementedTransformServiceServer

	reqAction    transformv1.TransformAction
	reqResponse  *transformv1.HttpResponse
	reqModified  *transformv1.HttpRequest
	reqAnnot     map[string]string
	lastReqProto *transformv1.TransformRequestRequest

	respAction    transformv1.TransformAction
	respModified  *transformv1.HttpResponse
	respAnnot     map[string]string
	lastRespProto *transformv1.TransformResponseRequest
}

func (f *fakeServer) TransformRequest(_ context.Context, in *transformv1.TransformRequestRequest) (*transformv1.TransformRequestResponse, error) {
	f.lastReqProto = in
	return &transformv1.TransformRequestResponse{
		Action:          f.reqAction,
		Response:        f.reqResponse,
		ModifiedRequest: f.reqModified,
		Annotations:     f.reqAnnot,
	}, nil
}

func (f *fakeServer) TransformResponse(_ context.Context, in *transformv1.TransformResponseRequest) (*transformv1.TransformResponseResponse, error) {
	f.lastRespProto = in
	return &transformv1.TransformResponseResponse{
		Action:           f.respAction,
		ModifiedResponse: f.respModified,
		Annotations:      f.respAnnot,
	}, nil
}

func startFakeServer(t *testing.T, srv *fakeServer) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := grpc.NewServer()
	transformv1.RegisterTransformServiceServer(s, srv)
	t.Cleanup(func() { s.Stop() })

	go func() { _ = s.Serve(lis) }()
	return lis.Addr().String()
}

func newTestTransform(t *testing.T, name, target string, sendReq, sendResp bool) *GRPCTransform {
	t.Helper()
	gt, err := newGRPCTransform(grpcConfig{
		Name:             name,
		Target:           target,
		SendRequestBody:  sendReq,
		SendResponseBody: sendResp,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = gt.Close() })
	return gt
}

func testContext() *transform.TransformContext {
	return &transform.TransformContext{}
}

func TestName(t *testing.T) {
	srv := &fakeServer{reqAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE}
	addr := startFakeServer(t, srv)

	gt := newTestTransform(t, "policy-engine", addr, false, false)
	require.Equal(t, "policy-engine", gt.Name())
}

func TestTransformRequest_Continue(t *testing.T) {
	srv := &fakeServer{reqAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE}
	addr := startFakeServer(t, srv)

	gt := newTestTransform(t, "test", addr, false, false)
	req, _ := http.NewRequest("GET", "https://example.com/foo", nil)
	req.Header.Set("X-Test", "hello")

	tctx := testContext()
	tctx.SNI = "example.com"
	result, err := gt.TransformRequest(context.Background(), tctx, req)

	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, result.Action)
	require.Equal(t, "example.com", srv.lastReqProto.GetContext().GetSni())
	require.Equal(t, "GET", srv.lastReqProto.GetRequest().GetMethod())
	require.Equal(t, "hello", srv.lastReqProto.GetRequest().GetHeaders()["X-Test"].GetValues()[0])
}

func TestTransformRequest_TunnelInfoInContext(t *testing.T) {
	srv := &fakeServer{reqAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE}
	addr := startFakeServer(t, srv)

	gt := newTestTransform(t, "test", addr, false, false)
	req, _ := http.NewRequest("GET", "https://example.com/foo", nil)
	tctx := &transform.TransformContext{
		Tunnel: &transform.TunnelInfo{
			Target: "example.com:443",
			RequestTransforms: []transform.TransformTrace{
				{
					Name: "auth",
					Annotations: map[string]any{
						"user_id": "alice",
						"count":   3,
						"vip":     true,
					},
				},
				{
					Name:        "policy",
					Annotations: map[string]any{"tier": "gold"},
				},
			},
		},
	}

	result, err := gt.TransformRequest(context.Background(), tctx, req)

	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, result.Action)
	tunnel := srv.lastReqProto.GetContext().GetTunnel()
	require.Equal(t, "example.com:443", tunnel.GetTarget())
	traces := tunnel.GetRequestTransforms()
	require.Len(t, traces, 2)
	require.Equal(t, "auth", traces[0].GetName())
	authAnn := traces[0].GetAnnotations().AsMap()
	require.Equal(t, "alice", authAnn["user_id"])
	require.Equal(t, float64(3), authAnn["count"])
	require.Equal(t, true, authAnn["vip"])
	require.Equal(t, "policy", traces[1].GetName())
	require.Equal(t, "gold", traces[1].GetAnnotations().AsMap()["tier"])
}

func TestTransformRequest_Reject(t *testing.T) {
	srv := &fakeServer{
		reqAction: transformv1.TransformAction_TRANSFORM_ACTION_REJECT,
		reqResponse: &transformv1.HttpResponse{
			StatusCode: 429,
			Body:       []byte("rate limited"),
		},
	}
	addr := startFakeServer(t, srv)

	gt := newTestTransform(t, "test", addr, true, false)
	req, _ := http.NewRequest("POST", "https://api.example.com/v1", nil)
	req.Body = transform.NewBufferedBody(io.NopCloser(bytes.NewReader([]byte("body"))), 1<<20)

	result, err := gt.TransformRequest(context.Background(), testContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, result.Action)
	require.NotNil(t, result.Response)
	require.Equal(t, 429, result.Response.StatusCode)

	body, _ := io.ReadAll(result.Response.Body)
	require.Equal(t, "rate limited", string(body))
}

func TestTransformRequest_ModifiesRequest(t *testing.T) {
	srv := &fakeServer{
		reqAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE,
		reqModified: &transformv1.HttpRequest{
			Headers: map[string]*transformv1.HeaderValues{
				"Authorization": {Values: []string{"Bearer injected"}},
			},
		},
	}
	addr := startFakeServer(t, srv)

	gt := newTestTransform(t, "test", addr, false, false)
	req, _ := http.NewRequest("GET", "https://example.com/", nil)

	result, err := gt.TransformRequest(context.Background(), testContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, result.Action)
	require.Equal(t, "Bearer injected", req.Header.Get("Authorization"))
}

func TestTransformRequest_Annotations(t *testing.T) {
	srv := &fakeServer{
		reqAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE,
		reqAnnot:  map[string]string{"policy": "allowed"},
	}
	addr := startFakeServer(t, srv)

	gt := newTestTransform(t, "test", addr, false, false)
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	tctx := testContext()

	_, err := gt.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)

	annotations := tctx.DrainAnnotations()
	require.Equal(t, "allowed", annotations["policy"])
}

func TestTransformResponse_Continue(t *testing.T) {
	srv := &fakeServer{
		respAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE,
	}
	addr := startFakeServer(t, srv)

	gt := newTestTransform(t, "test", addr, false, true)
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       transform.NewBufferedBody(io.NopCloser(bytes.NewReader([]byte(`{"ok":true}`))), 1<<20),
	}

	result, err := gt.TransformResponse(context.Background(), testContext(), req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, result.Action)
	require.Equal(t, int32(200), srv.lastRespProto.GetResponse().GetStatusCode())
	require.Equal(t, []byte(`{"ok":true}`), srv.lastRespProto.GetResponse().GetBody())
}

func TestTransformResponse_ModifiesResponse(t *testing.T) {
	srv := &fakeServer{
		respAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE,
		respModified: &transformv1.HttpResponse{
			StatusCode: 201,
			Body:       []byte("modified body"),
		},
	}
	addr := startFakeServer(t, srv)

	gt := newTestTransform(t, "test", addr, false, false)
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader([]byte("original"))),
	}

	result, err := gt.TransformResponse(context.Background(), testContext(), req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, result.Action)
	require.Equal(t, 201, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, "modified body", string(body))
}

func TestTransformResponse_Reject(t *testing.T) {
	srv := &fakeServer{
		respAction: transformv1.TransformAction_TRANSFORM_ACTION_REJECT,
		respModified: &transformv1.HttpResponse{
			StatusCode: 502,
			Body:       []byte("blocked"),
		},
	}
	addr := startFakeServer(t, srv)

	gt := newTestTransform(t, "test", addr, false, false)
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader([]byte("original"))),
	}

	result, err := gt.TransformResponse(context.Background(), testContext(), req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, result.Action)
	require.NotNil(t, result.Response)
	require.Equal(t, 502, result.Response.StatusCode)
}

// --- send body tests ---

func TestSendRequestBody_True(t *testing.T) {
	srv := &fakeServer{reqAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE}
	addr := startFakeServer(t, srv)

	gt := newTestTransform(t, "test", addr, true, false)
	req, _ := http.NewRequest("POST", "https://example.com/", nil)
	req.Body = transform.NewBufferedBody(io.NopCloser(bytes.NewReader([]byte("payload"))), 1<<20)

	_, err := gt.TransformRequest(context.Background(), testContext(), req)
	require.NoError(t, err)
	require.Equal(t, []byte("payload"), srv.lastReqProto.GetRequest().GetBody())
}

func TestSendRequestBody_False(t *testing.T) {
	srv := &fakeServer{reqAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE}
	addr := startFakeServer(t, srv)

	gt := newTestTransform(t, "test", addr, false, false)
	req, _ := http.NewRequest("POST", "https://example.com/", bytes.NewReader([]byte("payload")))

	_, err := gt.TransformRequest(context.Background(), testContext(), req)
	require.NoError(t, err)
	require.Empty(t, srv.lastReqProto.GetRequest().GetBody())

	// Original body should still be readable.
	body, _ := io.ReadAll(req.Body)
	require.Equal(t, "payload", string(body))
}

func TestSendResponseBody_True(t *testing.T) {
	srv := &fakeServer{respAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE}
	addr := startFakeServer(t, srv)

	gt := newTestTransform(t, "test", addr, false, true)
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       transform.NewBufferedBody(io.NopCloser(bytes.NewReader([]byte("response data"))), 1<<20),
	}

	_, err := gt.TransformResponse(context.Background(), testContext(), req, resp)
	require.NoError(t, err)
	require.Equal(t, []byte("response data"), srv.lastRespProto.GetResponse().GetBody())
}

func TestSendResponseBody_False(t *testing.T) {
	srv := &fakeServer{respAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE}
	addr := startFakeServer(t, srv)

	gt := newTestTransform(t, "test", addr, false, false)
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader([]byte("response data"))),
	}

	_, err := gt.TransformResponse(context.Background(), testContext(), req, resp)
	require.NoError(t, err)
	require.Empty(t, srv.lastRespProto.GetResponse().GetBody())
}

// --- factory / config tests ---

func TestFactory_ValidConfig(t *testing.T) {
	srv := &fakeServer{reqAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE}
	addr := startFakeServer(t, srv)

	f, err := transform.Lookup("grpc")
	require.NoError(t, err)

	cfgYAML := fmt.Sprintf(`name: test-svc
target: %s
send_request_body: true`, addr)

	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(cfgYAML), &node))

	tr, err := f(*node.Content[0], slog.Default())
	require.NoError(t, err)
	require.Equal(t, "test-svc", tr.Name())
}

func TestFactory_MissingName(t *testing.T) {
	f, err := transform.Lookup("grpc")
	require.NoError(t, err)

	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(`target: "localhost:9500"`), &node))

	_, err = f(*node.Content[0], slog.Default())
	require.Error(t, err)
	require.Contains(t, err.Error(), "name is required")
}

func TestFactory_MissingTarget(t *testing.T) {
	f, err := transform.Lookup("grpc")
	require.NoError(t, err)

	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(`name: test`), &node))

	_, err = f(*node.Content[0], slog.Default())
	require.Error(t, err)
	require.Contains(t, err.Error(), "target is required")
}

func TestFactory_TLS_CertWithoutKey(t *testing.T) {
	f, err := transform.Lookup("grpc")
	require.NoError(t, err)

	cfgYAML := `name: test
target: localhost:9500
tls:
  enabled: true
  cert: /some/cert.pem`

	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(cfgYAML), &node))

	_, err = f(*node.Content[0], slog.Default())
	require.Error(t, err)
	require.Contains(t, err.Error(), "both cert and key are required")
}

func TestFactory_TLS_BadCACert(t *testing.T) {
	f, err := transform.Lookup("grpc")
	require.NoError(t, err)

	cfgYAML := `name: test
target: localhost:9500
tls:
  enabled: true
  ca_cert: /nonexistent/ca.pem`

	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(cfgYAML), &node))

	_, err = f(*node.Content[0], slog.Default())
	require.Error(t, err)
	require.Contains(t, err.Error(), "reading ca_cert")
}

// --- rules tests ---

func TestRules_MatchingRequestForwarded(t *testing.T) {
	srv := &fakeServer{reqAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE}
	addr := startFakeServer(t, srv)

	gt, err := newGRPCTransform(grpcConfig{
		Name:   "test",
		Target: addr,
		Rules: []hostmatch.RuleConfig{
			{Host: "api.openai.com", Methods: []string{"POST"}, Paths: []string{"/v1/*"}},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = gt.Close() })

	req, _ := http.NewRequest("POST", "https://api.openai.com/v1/chat", nil)
	req.Host = "api.openai.com"

	result, err := gt.TransformRequest(context.Background(), testContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, result.Action)
	// Server was called.
	require.NotNil(t, srv.lastReqProto)
}

func TestRules_NonMatchingRequestSkipped(t *testing.T) {
	srv := &fakeServer{reqAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE}
	addr := startFakeServer(t, srv)

	gt, err := newGRPCTransform(grpcConfig{
		Name:   "test",
		Target: addr,
		Rules: []hostmatch.RuleConfig{
			{Host: "api.openai.com", Methods: []string{"POST"}},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = gt.Close() })

	req, _ := http.NewRequest("GET", "https://other.com/foo", nil)
	req.Host = "other.com"

	result, err := gt.TransformRequest(context.Background(), testContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, result.Action)
	// Server was NOT called.
	require.Nil(t, srv.lastReqProto)
}

func TestRules_MethodMismatchSkipped(t *testing.T) {
	srv := &fakeServer{reqAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE}
	addr := startFakeServer(t, srv)

	gt, err := newGRPCTransform(grpcConfig{
		Name:   "test",
		Target: addr,
		Rules: []hostmatch.RuleConfig{
			{Host: "api.openai.com", Methods: []string{"POST"}},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = gt.Close() })

	req, _ := http.NewRequest("GET", "https://api.openai.com/v1/models", nil)
	req.Host = "api.openai.com"

	result, err := gt.TransformRequest(context.Background(), testContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, result.Action)
	require.Nil(t, srv.lastReqProto)
}

func TestRules_NoRulesMatchesAll(t *testing.T) {
	srv := &fakeServer{reqAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE}
	addr := startFakeServer(t, srv)

	gt := newTestTransform(t, "test", addr, false, false)
	req, _ := http.NewRequest("GET", "https://anything.com/whatever", nil)
	req.Host = "anything.com"

	_, err := gt.TransformRequest(context.Background(), testContext(), req)
	require.NoError(t, err)
	require.NotNil(t, srv.lastReqProto)
}

func TestRules_ResponseAlsoFiltered(t *testing.T) {
	srv := &fakeServer{
		respAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE,
	}
	addr := startFakeServer(t, srv)

	gt, err := newGRPCTransform(grpcConfig{
		Name:   "test",
		Target: addr,
		Rules:  []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = gt.Close() })

	req, _ := http.NewRequest("GET", "https://other.com/", nil)
	req.Host = "other.com"
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader([]byte("body"))),
	}

	result, err := gt.TransformResponse(context.Background(), testContext(), req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, result.Action)
	require.Nil(t, srv.lastRespProto)
}

func TestRules_InvalidConfig_HostAndCIDR(t *testing.T) {
	_, err := newGRPCTransform(grpcConfig{
		Name:   "test",
		Target: "localhost:9500",
		Rules:  []hostmatch.RuleConfig{{Host: "example.com", CIDR: "10.0.0.0/8"}},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "mutually exclusive")
}

func TestRules_InvalidConfig_NeitherHostNorCIDR(t *testing.T) {
	_, err := newGRPCTransform(grpcConfig{
		Name:   "test",
		Target: "localhost:9500",
		Rules:  []hostmatch.RuleConfig{{Methods: []string{"GET"}}},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "one of host or cidr is required")
}

// --- uncapped response body test ---

func TestSendResponseBody_UncappedDefault(t *testing.T) {
	srv := &fakeServer{respAction: transformv1.TransformAction_TRANSFORM_ACTION_CONTINUE}
	addr := startFakeServer(t, srv)

	gt := newTestTransform(t, "test", addr, false, true)
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	bigBody := bytes.Repeat([]byte("x"), 2<<20) // 2 MiB
	// Wrap in BufferedBody with 0 maxBytes (uncapped).
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       transform.NewBufferedBody(io.NopCloser(bytes.NewReader(bigBody)), 0),
	}

	_, err := gt.TransformResponse(context.Background(), testContext(), req, resp)
	require.NoError(t, err)
	require.Equal(t, bigBody, srv.lastRespProto.GetResponse().GetBody())
}

// A plugin that replaces the body of a request whose body was cut off at the
// proxy's limit built its replacement from the truncated bytes, so the
// request stays marked as truncated for later transforms (aws_auth).
func TestApplyModifiedRequest_CarriesTruncation(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		limit    int64
		wantFlag bool
	}{
		{name: "complete original", body: "short", limit: 1 << 20, wantFlag: false},
		{name: "truncated original", body: "a body longer than the limit", limit: 4, wantFlag: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "https://example.com/x", nil)
			require.NoError(t, err)
			original := transform.NewBufferedBody(io.NopCloser(bytes.NewReader([]byte(tt.body))), tt.limit)
			sent, err := io.ReadAll(original) // the body was buffered to send it to the plugin
			require.NoError(t, err)
			req.Body = original

			applyModifiedRequest(&transformv1.HttpRequest{Body: []byte("a much longer replacement body from the plugin")}, req, sent, true)

			replaced := transform.RequireBufferedBody(req.Body)
			require.Equal(t, tt.wantFlag, replaced.Truncated())
			require.Equal(t, int64(replaced.Len()), req.ContentLength)
		})
	}
}

// A plugin may return a full modified_request that echoes the body byte for
// byte while it edits only headers. That body is the client's: it must not be
// marked replaced, or a later aws_auth refuses an aws-chunked upload whose
// bytes nobody changed (chunked_upload_body_rewritten).
func TestApplyModifiedRequest_ReplacedOnlyWhenBytesDiffer(t *testing.T) {
	const clientBody = "10;chunk-signature=x\r\n0123456789abcdef\r\n0\r\n"
	tests := []struct {
		name         string
		returned     []byte
		bodySent     bool
		wantReplaced bool
		wantBody     string
	}{
		{name: "echoed unchanged", returned: []byte(clientBody), bodySent: true, wantReplaced: false, wantBody: clientBody},
		{name: "changed by the plugin", returned: []byte("rewritten"), bodySent: true, wantReplaced: true, wantBody: "rewritten"},
		{name: "body not sent, plugin supplies one", returned: []byte(clientBody), bodySent: false, wantReplaced: true, wantBody: clientBody},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPut, "https://bucket.s3.amazonaws.com/key", nil)
			require.NoError(t, err)
			original := transform.NewBufferedBody(io.NopCloser(bytes.NewReader([]byte(clientBody))), 0)
			var sent []byte
			if tt.bodySent {
				sent, err = io.ReadAll(original) // buffered to send it to the plugin
				require.NoError(t, err)
			}
			req.Body = original
			req.ContentLength = int64(len(clientBody))

			applyModifiedRequest(&transformv1.HttpRequest{
				Headers: map[string]*transformv1.HeaderValues{"X-Plugin": {Values: []string{"1"}}},
				Body:    tt.returned,
			}, req, sent, tt.bodySent)

			body := transform.RequireBufferedBody(req.Body)
			require.Equal(t, tt.wantReplaced, body.Replaced())
			got, err := io.ReadAll(body)
			require.NoError(t, err)
			require.Equal(t, tt.wantBody, string(got), "the next transform reads the body from the start")
			require.Equal(t, "1", req.Header.Get("X-Plugin"), "header edits still apply")
			if !tt.wantReplaced {
				require.Same(t, original, body, "the client's body is kept")
			}
		})
	}
}
