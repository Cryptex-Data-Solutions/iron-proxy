package awsauth

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

// The write policy (placeholder_access_key_id set): requests signed with the
// placeholder key are re-signed; anything else passes untouched if it is a
// read, or if an earlier transform injected a credential the proxy holds,
// and is rejected otherwise.

const (
	placeholderKeyID = "AKIAIOSFODNN7EXAMPLE" // what signedRequest signs with
	foreignKeyID     = "AKIAFOREIGNKEYEXAMPL"
	realKeyID        = "AKIAREALKEYEXAMPLE00"
)

const writePolicyYAML = minimalYAML + `
placeholder_access_key_id: "` + placeholderKeyID + `"
`

func writePolicyTransform(t *testing.T, cfgYAML string) *AWSAuth {
	t.Helper()
	srcs := map[string]secrets.Source{
		"AWS_ACCESS_KEY_ID":     &staticSource{name: "access", value: realKeyID},
		"AWS_SECRET_ACCESS_KEY": &staticSource{name: "secret", value: "real-secret"},
	}
	return buildTransformWith(t, cfgYAML, mapBuilder(srcs))
}

// foreignSignedRequest signs like signedRequest, but with someone else's key.
func foreignSignedRequest(t *testing.T, method, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, http.NoBody)
	require.NoError(t, err)
	req.Body = transform.NewBufferedBody(http.NoBody, 0)
	creds := aws.Credentials{AccessKeyID: foreignKeyID, SecretAccessKey: "attacker-secret"}
	require.NoError(t, v4.NewSigner().SignHTTP(context.Background(), creds, req, emptyPayloadSHA256, "s3", "us-east-1", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)))
	return req
}

func plainRequest(t *testing.T, method, rawURL, authorization string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, http.NoBody)
	require.NoError(t, err)
	req.Body = transform.NewBufferedBody(http.NoBody, 0)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	return req
}

const presignedQuery = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20250101T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=abc123&X-Amz-Credential="

func TestWritePolicy(t *testing.T) {
	basicECR := "Basic " + base64.StdEncoding.EncodeToString([]byte("AWS:some-registry-token"))
	registry := "https://123456789012.dkr.ecr.af-south-1.amazonaws.com"

	tests := []struct {
		name         string
		build        func(t *testing.T) *http.Request
		injectedBy   string // set before aws_auth runs, as credential_mask would
		wantReject   bool
		wantStatus   int
		wantResigned bool // Authorization now carries the real key ID
	}{
		{
			name: "placeholder-signed write is re-signed",
			build: func(t *testing.T) *http.Request {
				return signedRequest(t, "POST", "https://sts.amazonaws.com/", "us-east-1", "sts", []byte("Action=GetCallerIdentity"), 0)
			},
			wantResigned: true,
		},
		{
			name: "placeholder-signed read is re-signed",
			build: func(t *testing.T) *http.Request {
				return signedRequest(t, "GET", "https://my-bucket.s3.af-south-1.amazonaws.com/key", "af-south-1", "s3", nil, 0)
			},
			wantResigned: true,
		},
		{
			name: "foreign-signed read passes untouched",
			build: func(t *testing.T) *http.Request {
				return foreignSignedRequest(t, "GET", "https://their-bucket.s3.amazonaws.com/x")
			},
		},
		{
			name: "foreign-signed write is rejected",
			build: func(t *testing.T) *http.Request {
				return foreignSignedRequest(t, "PUT", "https://their-bucket.s3.amazonaws.com/x")
			},
			wantReject: true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:  "ECR registry Basic-auth read passes untouched",
			build: func(t *testing.T) *http.Request { return plainRequest(t, "GET", registry+"/v2/", basicECR) },
		},
		{
			name: "ECR registry Basic-auth write without an injected credential is rejected",
			build: func(t *testing.T) *http.Request {
				return plainRequest(t, "PUT", registry+"/v2/repo/manifests/latest", basicECR)
			},
			wantReject: true,
			wantStatus: http.StatusForbidden,
		},
		{
			name: "ECR registry Basic-auth write with a credential_mask swap passes untouched",
			build: func(t *testing.T) *http.Request {
				return plainRequest(t, "PUT", registry+"/v2/repo/manifests/latest", basicECR)
			},
			injectedBy: "credential_mask",
		},
		{
			name: "AWS-presigned layer download passes untouched",
			build: func(t *testing.T) *http.Request {
				return plainRequest(t, "GET", "https://prod-af-south-1-starport-layer-bucket.s3.af-south-1.amazonaws.com/abc?"+presignedQuery+"ASIAAWSSERVICEKEY000%2F20250101%2Faf-south-1%2Fs3%2Faws4_request", "")
			},
		},
		{
			name: "AWS-presigned upload is rejected",
			build: func(t *testing.T) *http.Request {
				return plainRequest(t, "PUT", "https://their-bucket.s3.amazonaws.com/x?"+presignedQuery+foreignKeyID+"%2F20250101%2Fus-east-1%2Fs3%2Faws4_request", "")
			},
			wantReject: true,
			wantStatus: http.StatusForbidden,
		},
		{
			name: "URL presigned with the placeholder key is rejected (not supported)",
			build: func(t *testing.T) *http.Request {
				return plainRequest(t, "GET", "https://my-bucket.s3.amazonaws.com/x?"+presignedQuery+placeholderKeyID+"%2F20250101%2Fus-east-1%2Fs3%2Faws4_request", "")
			},
			wantReject: true,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "placeholder-signed request that also carries a presigned query is rejected",
			build: func(t *testing.T) *http.Request {
				return signedRequest(t, "GET", "https://my-bucket.s3.amazonaws.com/x?"+presignedQuery+foreignKeyID+"%2F20250101%2Fus-east-1%2Fs3%2Faws4_request", "us-east-1", "s3", nil, 0)
			},
			wantReject: true,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "unsigned POST to someone's API Gateway is rejected",
			build: func(t *testing.T) *http.Request {
				return plainRequest(t, "POST", "https://abc123.execute-api.us-east-1.amazonaws.com/collect", "Bearer some-jwt")
			},
			wantReject: true,
			wantStatus: http.StatusForbidden,
		},
		{
			name: "unsigned HEAD passes untouched",
			build: func(t *testing.T) *http.Request {
				return plainRequest(t, "HEAD", "https://public-bucket.s3.amazonaws.com/x", "")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := writePolicyTransform(t, writePolicyYAML)
			req := tc.build(t)
			authBefore := req.Header.Get("Authorization")
			urlBefore := req.URL.String()

			tctx := newContext()
			if tc.injectedBy != "" {
				tctx.MarkCredentialInjected(tc.injectedBy)
			}
			res, err := a.TransformRequest(context.Background(), tctx, req)
			require.NoError(t, err)

			if tc.wantReject {
				require.Equal(t, transform.ActionReject, res.Action)
				require.Equal(t, tc.wantStatus, res.Response.StatusCode)
				return
			}
			require.Equal(t, transform.ActionContinue, res.Action)
			if tc.wantResigned {
				require.Contains(t, req.Header.Get("Authorization"), "Credential="+realKeyID+"/")
				require.Contains(t, tctx.CredentialsInjectedBy(), "aws_auth")
				return
			}
			require.Equal(t, authBefore, req.Header.Get("Authorization"), "must pass untouched")
			require.Equal(t, urlBefore, req.URL.String(), "must pass untouched")
			require.NotContains(t, tctx.CredentialsInjectedBy(), "aws_auth", "nothing was signed by the proxy")
		})
	}
}

// Without placeholder_access_key_id the upstream behaviour is unchanged:
// anything not SigV4-signed is rejected, and a foreign key is re-signed.
func TestWritePolicy_OffByDefault(t *testing.T) {
	a := writePolicyTransform(t, minimalYAML)

	req := plainRequest(t, "GET", "https://123456789012.dkr.ecr.af-south-1.amazonaws.com/v2/", "Basic eA==")
	res, err := a.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
	require.Equal(t, http.StatusBadRequest, res.Response.StatusCode)

	req = foreignSignedRequest(t, "PUT", "https://their-bucket.s3.amazonaws.com/x")
	res, err = a.TransformRequest(context.Background(), newContext(), req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Contains(t, req.Header.Get("Authorization"), "Credential="+realKeyID+"/")
}

// Re-signing replaces headers only. A presigned URL keeps its query
// signature, so re-signing it would send two signatures, which the upstream
// refuses. It is refused here instead, with or without the write policy.
func TestPresignedURLIsNotResigned(t *testing.T) {
	presigned := "https://my-bucket.s3.amazonaws.com/x?" + presignedQuery + foreignKeyID + "%2F20250101%2Fus-east-1%2Fs3%2Faws4_request"

	tests := []struct {
		name  string
		cfg   string
		build func(t *testing.T) *http.Request
	}{
		{
			name:  "write policy off: presigned URL",
			cfg:   minimalYAML,
			build: func(t *testing.T) *http.Request { return plainRequest(t, "GET", presigned, "") },
		},
		{
			name: "write policy off: header-signed request with a presigned query",
			cfg:  minimalYAML,
			build: func(t *testing.T) *http.Request {
				return signedRequest(t, "PUT", presigned, "us-east-1", "s3", []byte("x"), 0)
			},
		},
		{
			name: "write policy on: placeholder-signed request with a presigned query",
			cfg:  writePolicyYAML,
			build: func(t *testing.T) *http.Request {
				return signedRequest(t, "PUT", presigned, "us-east-1", "s3", []byte("x"), 0)
			},
		},
		{
			name: "only X-Amz-Signature in the query",
			cfg:  minimalYAML,
			build: func(t *testing.T) *http.Request {
				return signedRequest(t, "GET", "https://my-bucket.s3.amazonaws.com/x?X-Amz-Signature=abc123", "us-east-1", "s3", nil, 0)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := writePolicyTransform(t, tc.cfg)
			req := tc.build(t)
			tctx := newContext()
			res, err := a.TransformRequest(context.Background(), tctx, req)
			require.NoError(t, err)
			require.Equal(t, transform.ActionReject, res.Action)
			require.Equal(t, http.StatusBadRequest, res.Response.StatusCode)
			require.NotContains(t, tctx.CredentialsInjectedBy(), "aws_auth", "nothing may be signed")
		})
	}

	t.Run("an ordinary query string is still re-signed", func(t *testing.T) {
		a := writePolicyTransform(t, minimalYAML)
		req := signedRequest(t, "GET", "https://my-bucket.s3.amazonaws.com/?list-type=2&prefix=a", "us-east-1", "s3", nil, 0)
		res, err := a.TransformRequest(context.Background(), newContext(), req)
		require.NoError(t, err)
		require.Equal(t, transform.ActionContinue, res.Action)
		require.Contains(t, req.Header.Get("Authorization"), "Credential="+realKeyID+"/")
	})
}
