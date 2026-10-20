package awsauth

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

const placeholderAuth = "AWS4-HMAC-SHA256 Credential=PLACEHOLDER/20260101/af-south-1/s3/aws4_request, SignedHeaders=host, Signature=abc"

// signedHeaderList returns the SignedHeaders entries of a SigV4
// Authorization header value.
func signedHeaderList(t *testing.T, auth string) []string {
	t.Helper()
	for _, part := range strings.Split(auth, ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(part), "SignedHeaders="); ok {
			return strings.Split(v, ";")
		}
	}
	t.Fatalf("no SignedHeaders in %q", auth)
	return nil
}

// TestTransformRequest_DeclaredPayloadMode covers the payload modes a client
// can declare in X-Amz-Content-Sha256, signed with the real signer. Current
// AWS SDKs upload to S3 as aws-chunked bodies with a checksum trailer and no
// Content-Length; those must be re-signed without reading the body.
func TestTransformRequest_DeclaredPayloadMode(t *testing.T) {
	srcs := map[string]secrets.Source{
		"AWS_ACCESS_KEY_ID":     &staticSource{name: "access", value: "AKIAREALKEY"},
		"AWS_SECRET_ACCESS_KEY": &staticSource{name: "secret", value: "real-secret"},
	}
	// The body limit is far smaller than the body, so any attempt to buffer
	// it shows up as a truncated body.
	const smallLimit = 16
	body := strings.Repeat("x", 4096)

	tests := []struct {
		name            string
		unsignedPayload bool   // the unsigned_payload config option
		declared        string // X-Amz-Content-Sha256 sent by the client
		contentLength   int64  // -1 = chunked transfer, as the SDKs send it
		// preBuffered simulates an earlier transform (body_capture, secrets
		// matching in the body) that already read the body, with this body
		// limit; 0 means the body is still unread.
		preBuffered int64
		wantAction  transform.TransformAction
		wantStatus  int    // for rejections
		wantPayload string // signed X-Amz-Content-Sha256 on success
	}{
		// Declared modes, body unread: streamed in full whatever its size.
		{
			name:          "SDK default: chunked upload with checksum trailer",
			declared:      "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
			contentLength: -1,
			wantAction:    transform.ActionContinue,
			wantPayload:   "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
		},
		{
			name:          "client declares UNSIGNED-PAYLOAD",
			declared:      "UNSIGNED-PAYLOAD",
			contentLength: int64(len(body)),
			wantAction:    transform.ActionContinue,
			wantPayload:   "UNSIGNED-PAYLOAD",
		},
		{
			name:            "unsigned_payload set: trailer mode is still kept",
			unsignedPayload: true,
			declared:        "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
			contentLength:   -1,
			wantAction:      transform.ActionContinue,
			wantPayload:     "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
		},
		{
			name:            "unsigned_payload set: declared hex hash is signed as UNSIGNED-PAYLOAD",
			unsignedPayload: true,
			declared:        sha256Hex([]byte(body)),
			contentLength:   int64(len(body)),
			wantAction:      transform.ActionContinue,
			wantPayload:     "UNSIGNED-PAYLOAD",
		},

		// Body-signing streams are refused.
		{
			name:          "per-chunk signed stream is refused",
			declared:      "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
			contentLength: int64(len(body)),
			wantAction:    transform.ActionReject,
			wantStatus:    http.StatusBadRequest,
		},
		{
			name:          "per-chunk signed stream with trailer is refused",
			declared:      "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
			contentLength: -1,
			wantAction:    transform.ActionReject,
			wantStatus:    http.StatusBadRequest,
		},
		{
			name:          "event-stream signing is refused",
			declared:      "STREAMING-AWS4-HMAC-SHA256-EVENTS",
			contentLength: -1,
			wantAction:    transform.ActionReject,
			wantStatus:    http.StatusBadRequest,
		},
		{
			name:            "unsigned_payload set: per-chunk signed stream is still refused",
			unsignedPayload: true,
			declared:        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
			contentLength:   int64(len(body)),
			wantAction:      transform.ActionReject,
			wantStatus:      http.StatusBadRequest,
		},

		// A declared hex hash is recalculated, so the body limit applies.
		{
			name:          "declared hex hash is still re-hashed, so the body limit applies",
			declared:      sha256Hex([]byte(body)),
			contentLength: int64(len(body)),
			wantAction:    transform.ActionReject,
			wantStatus:    http.StatusRequestEntityTooLarge,
		},

		// An earlier transform already buffered (and so truncated) the body.
		{
			name:          "already buffered and truncated: trailer mode refused",
			declared:      "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
			contentLength: int64(len(body)),
			preBuffered:   smallLimit,
			wantAction:    transform.ActionReject,
			wantStatus:    http.StatusRequestEntityTooLarge,
		},
		{
			name:          "already buffered, chunked: truncation undetectable, refused",
			declared:      "UNSIGNED-PAYLOAD",
			contentLength: -1,
			preBuffered:   smallLimit,
			wantAction:    transform.ActionReject,
			wantStatus:    http.StatusBadRequest,
		},
		{
			name:            "unsigned_payload set: already buffered and truncated is refused",
			unsignedPayload: true,
			contentLength:   int64(len(body)),
			preBuffered:     smallLimit,
			wantAction:      transform.ActionReject,
			wantStatus:      http.StatusRequestEntityTooLarge,
		},
		{
			name:          "already buffered and complete: declared mode kept",
			declared:      "UNSIGNED-PAYLOAD",
			contentLength: int64(len(body)),
			preBuffered:   1 << 20,
			wantAction:    transform.ActionContinue,
			wantPayload:   "UNSIGNED-PAYLOAD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := minimalYAML
			if tt.unsignedPayload {
				cfg += "unsigned_payload: true\n"
			}
			a := buildTransformWith(t, cfg, mapBuilder(srcs))

			limit := int64(smallLimit)
			if tt.preBuffered > 0 {
				limit = tt.preBuffered
			}
			req, err := http.NewRequest(http.MethodPut, "https://bucket.s3.af-south-1.amazonaws.com/key", nil)
			require.NoError(t, err)
			buffered := transform.NewBufferedBody(io.NopCloser(strings.NewReader(body)), limit)
			req.Body = buffered
			req.ContentLength = tt.contentLength
			if tt.preBuffered > 0 {
				_, err := io.ReadAll(buffered) // an earlier transform reads the body...
				require.NoError(t, err)
				buffered.Reset() // ...and rewinds it, as the pipeline does
			}
			req.Header.Set("Authorization", placeholderAuth)
			if tt.declared != "" {
				req.Header.Set("X-Amz-Content-Sha256", tt.declared)
			}
			req.Header.Set("Content-Encoding", "aws-chunked")
			req.Header.Set("X-Amz-Decoded-Content-Length", "4096")
			req.Header.Set("X-Amz-Trailer", "x-amz-checksum-crc64nvme")

			res, err := a.TransformRequest(context.Background(), newContext(), req)
			require.NoError(t, err)
			require.Equal(t, tt.wantAction, res.Action)

			if tt.wantAction == transform.ActionReject {
				require.Equal(t, tt.wantStatus, res.Response.StatusCode)
				require.Equal(t, placeholderAuth, req.Header.Get("Authorization"), "a refused request must not be signed")
				return
			}

			// Re-signed with the real key, keeping the declared mode.
			auth := req.Header.Get("Authorization")
			require.Contains(t, auth, "Credential=AKIAREALKEY/")
			require.Equal(t, tt.wantPayload, req.Header.Get("X-Amz-Content-Sha256"))

			// The aws-chunked headers S3 needs to decode the body are kept and
			// covered by the new signature. Content-Length is signed only when
			// known, and Transfer-Encoding never is.
			signed := signedHeaderList(t, auth)
			require.Equal(t, "aws-chunked", req.Header.Get("Content-Encoding"))
			for _, h := range []string{"content-encoding", "host", "x-amz-content-sha256", "x-amz-date", "x-amz-decoded-content-length", "x-amz-trailer"} {
				require.Contains(t, signed, h)
			}
			if tt.contentLength > 0 {
				require.Contains(t, signed, "content-length")
			} else {
				require.NotContains(t, signed, "content-length")
			}
			require.NotContains(t, signed, "transfer-encoding")

			// The proxy forwards the whole body (StreamingReader is what it
			// sends upstream). If nothing read it before, it is still unread.
			if tt.preBuffered == 0 {
				require.Equal(t, -1, buffered.Len(), "body must not be buffered")
			}
			sent, err := io.ReadAll(buffered.StreamingReader())
			require.NoError(t, err)
			require.Equal(t, body, string(sent))
		})
	}
}

// TestRefusedStreamingMode_AuditLabel checks what the audit log records for a
// refused STREAMING-* value, through a real pipeline where an earlier
// secrets transform (matching every header, its default) swaps a real secret
// into the client's X-Amz-Content-Sha256. The header value must never reach
// the audit log: only a known mode's name, or a fixed label.
func TestRefusedStreamingMode_AuditLabel(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", realKeyID)
	t.Setenv("AWS_SECRET_ACCESS_KEY", "real-secret")
	t.Setenv("API_TOKEN", "real-api-token-value")

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
  - source: {type: env, var: API_TOKEN}
    rules: [{host: "*.s3.af-south-1.amazonaws.com"}]
    replace:
      proxy_value: "proxy-api-token"
`)
	awsTr := build("aws_auth", minimalYAML)
	pipeline := transform.NewPipeline([]transform.Transformer{secretsTr, awsTr}, transform.BodyLimits{}, slog.Default())

	tests := []struct {
		name      string
		declared  string
		wantLabel string
	}{
		{
			name:      "known mode is named",
			declared:  "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
			wantLabel: "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
		},
		{
			name:      "client value with a swapped-in secret is not logged",
			declared:  "STREAMING-proxy-api-token",
			wantLabel: "unrecognised_streaming_mode",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPut, "https://bucket.s3.af-south-1.amazonaws.com/key", nil)
			require.NoError(t, err)
			req.Body = transform.NewBufferedBody(http.NoBody, 1<<20)
			req.Header.Set("Authorization", placeholderAuth)
			req.Header.Set("X-Amz-Content-Sha256", tt.declared)

			var traces []transform.TransformTrace
			rejected, err := pipeline.ProcessRequest(context.Background(), newContext(), req, &traces)
			require.NoError(t, err)
			require.NotNil(t, rejected)
			require.Equal(t, http.StatusBadRequest, rejected.StatusCode)
			if strings.Contains(tt.declared, "proxy-api-token") {
				// Prove the scenario is real: secrets did swap the secret in.
				require.Equal(t, "STREAMING-real-api-token-value", req.Header.Get("X-Amz-Content-Sha256"))
			}

			var label any
			for _, tr := range traces {
				for k, v := range tr.Annotations {
					require.NotContains(t, fmt.Sprint(v), "real-api-token-value", "annotation %q leaks the secret", k)
				}
				if tr.Name == "aws_auth" {
					label = tr.Annotations["payload"]
				}
			}
			require.Equal(t, tt.wantLabel, label)
		})
	}
}
