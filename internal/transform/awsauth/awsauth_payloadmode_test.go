package awsauth

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

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
	// it shows up as a 413 body_truncated rejection.
	const bodyLimit = 16
	body := strings.Repeat("x", 4096)

	tests := []struct {
		name            string
		unsignedPayload bool   // the unsigned_payload config option
		declared        string // X-Amz-Content-Sha256 sent by the client
		contentLength   int64  // -1 = chunked transfer, as the SDKs send it
		wantAction      transform.TransformAction
		wantStatus      int    // for rejections
		wantPayload     string // signed X-Amz-Content-Sha256 on success
	}{
		{
			name:            "unsigned_payload set: trailer mode is still kept",
			unsignedPayload: true,
			declared:        "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
			contentLength:   -1,
			wantAction:      transform.ActionContinue,
			wantPayload:     "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
		},
		{
			name:            "unsigned_payload set: per-chunk signed stream is still refused",
			unsignedPayload: true,
			declared:        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
			contentLength:   int64(len(body)),
			wantAction:      transform.ActionReject,
			wantStatus:      http.StatusBadRequest,
		},
		{
			name:            "unsigned_payload set: declared hex hash is signed as UNSIGNED-PAYLOAD",
			unsignedPayload: true,
			declared:        sha256Hex([]byte(body)),
			contentLength:   int64(len(body)),
			wantAction:      transform.ActionContinue,
			wantPayload:     "UNSIGNED-PAYLOAD",
		},
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
			name:          "declared hex hash is still re-hashed, so the body limit applies",
			declared:      sha256Hex([]byte(body)),
			contentLength: int64(len(body)),
			wantAction:    transform.ActionReject,
			wantStatus:    http.StatusRequestEntityTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := minimalYAML
			if tt.unsignedPayload {
				cfg += "unsigned_payload: true\n"
			}
			a := buildTransformWith(t, cfg, mapBuilder(srcs))

			req, err := http.NewRequest(http.MethodPut, "https://bucket.s3.af-south-1.amazonaws.com/key", nil)
			require.NoError(t, err)
			req.Body = transform.NewBufferedBody(io.NopCloser(strings.NewReader(body)), bodyLimit)
			req.ContentLength = tt.contentLength
			req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=PLACEHOLDER/20260101/af-south-1/s3/aws4_request, SignedHeaders=host, Signature=abc")
			req.Header.Set("X-Amz-Content-Sha256", tt.declared)
			req.Header.Set("Content-Encoding", "aws-chunked")
			req.Header.Set("X-Amz-Decoded-Content-Length", "4096")
			req.Header.Set("X-Amz-Trailer", "x-amz-checksum-crc64nvme")

			res, err := a.TransformRequest(context.Background(), newContext(), req)
			require.NoError(t, err)
			require.Equal(t, tt.wantAction, res.Action)

			if tt.wantAction == transform.ActionReject {
				require.Equal(t, tt.wantStatus, res.Response.StatusCode)
				return
			}

			// Re-signed with the real key, keeping the declared mode.
			auth := req.Header.Get("Authorization")
			require.Contains(t, auth, "Credential=AKIAREALKEY/")
			require.Equal(t, tt.wantPayload, req.Header.Get("X-Amz-Content-Sha256"))
			// The aws-chunked headers S3 needs to decode the body are kept
			// and covered by the new signature.
			require.Equal(t, "aws-chunked", req.Header.Get("Content-Encoding"))
			for _, h := range []string{"content-encoding", "x-amz-content-sha256", "x-amz-decoded-content-length", "x-amz-trailer"} {
				require.Contains(t, auth, h, "signed headers should include %s", h)
			}
			// The body was never buffered, and the proxy forwards all of it
			// (StreamingReader is what the proxy sends upstream).
			buffered := transform.RequireBufferedBody(req.Body)
			require.Equal(t, -1, buffered.Len(), "body must not be buffered")
			sent, err := io.ReadAll(buffered.StreamingReader())
			require.NoError(t, err)
			require.Equal(t, body, string(sent))
		})
	}
}
