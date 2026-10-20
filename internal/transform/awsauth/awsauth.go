// Package awsauth implements an AWS Signature Version 4 request-signing
// transform. The inbound request is expected to already carry a SigV4
// signature produced by any AWS SDK using placeholder credentials. This
// transform reads the region and service from the inbound credential scope,
// strips the placeholder signature, and re-signs the request with real
// credentials. This lets a single transform entry handle every AWS service a
// client speaks to without enumerating them in config.
//
// Credentials come from one of two sources, mutually exclusive:
//   - access_key_id + secret_access_key: each backed by any registered secret
//     source (env, aws_sm, aws_ssm, 1password, ...). Best for calling AWS
//     from outside AWS with long-lived static keys.
//   - credentials_provider: a structured block dispatching on a type field.
//     The "workload_identity" type defers to the AWS SDK default credential
//     chain, which natively resolves IRSA, EKS Pod Identity, IMDSv2, env
//     vars, shared profiles, and SSO. Best for pod-bound rotating creds the
//     agent should never see.
//
// Like hmac_sign, this requires MITM mode: sni-only mode has no method, path,
// or body to sign.
//
// The payload hash is chosen in this order (see payloadHash):
//   - The client declared UNSIGNED-PAYLOAD or STREAMING-UNSIGNED-PAYLOAD-TRAILER
//     (current SDKs' checksummed S3 uploads): kept, and the body is streamed
//     unread. Other STREAMING-* modes are refused.
//   - unsigned_payload: true: signed as UNSIGNED-PAYLOAD, body unread.
//   - Otherwise the body is hashed. A truncated body would produce an invalid
//     signature, so bodies shorter than Content-Length and chunked bodies are
//     rejected by default; allow_chunked_body: true opts out of the chunked
//     check.
//
// A body an earlier transform already buffered may have been cut off at the
// proxy's body limit, so it gets the same length checks in every case. A
// transform placed after aws_auth cannot be checked here: if it reads or
// rewrites the body, the request no longer matches its signature (or, for an
// unread body, is cut off after signing). Place aws_auth after every
// transform that reads or rewrites request bodies.
//
// Setting placeholder_access_key_id (Cryptex addition) replaces "re-sign
// every SigV4 request, reject everything else" with a write policy: only
// requests signed with that placeholder key are re-signed, reads pass
// untouched, and a write passes only if it carries a credential the proxy
// put there. See writePolicy.
package awsauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
)

func init() {
	transform.Register("aws_auth", factory)
}

const (
	// unsignedPayload is the literal placeholder AWS accepts in lieu of a real
	// SHA-256 payload hash. S3, Bedrock streaming, etc. document this value.
	unsignedPayload = "UNSIGNED-PAYLOAD"
	// streamingUnsignedPayloadTrailer is the payload mode current AWS SDKs
	// declare for checksummed aws-chunked uploads over HTTPS: the body is not
	// hashed into the signature, and a checksum trailer follows the chunks.
	streamingUnsignedPayloadTrailer = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"

	// emptyPayloadSHA256 is the hex SHA-256 of the empty string, used when the
	// request has no body. Per the SDK docs SignHTTP always requires a payload
	// hash, even for empty bodies.
	emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	sigV4Algorithm = "AWS4-HMAC-SHA256"
)

type config struct {
	AccessKeyID         yaml.Node              `yaml:"access_key_id,omitempty"`
	SecretAccessKey     yaml.Node              `yaml:"secret_access_key,omitempty"`
	CredentialsProvider yaml.Node              `yaml:"credentials_provider,omitempty"`
	AllowedRegions      []string               `yaml:"allowed_regions,omitempty"`
	AllowedServices     []string               `yaml:"allowed_services,omitempty"`
	UnsignedPayload     bool                   `yaml:"unsigned_payload,omitempty"`
	AllowChunkedBody    bool                   `yaml:"allow_chunked_body,omitempty"`
	Rules               []hostmatch.RuleConfig `yaml:"rules"`

	// PlaceholderAccessKeyID turns on the write policy (see writePolicy).
	// It is the access key ID the client's placeholder credentials use: a
	// public value, not a secret. Empty keeps the upstream behaviour: every
	// SigV4 request is re-signed and anything unsigned is rejected.
	PlaceholderAccessKeyID string `yaml:"placeholder_access_key_id,omitempty"`
}

// sourceBuilder is the signature of secrets.BuildSource, factored out so tests
// can substitute a stub builder.
type sourceBuilder func(yaml.Node, *slog.Logger) (secrets.Source, error)

// signFunc is the part of the AWS SDK v4 signer the transform uses. Factored
// into a function value so tests can inject deterministic behavior without
// reaching for the real signer.
type signFunc func(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash, service, region string, signingTime time.Time) error

// Credential provider kinds, annotated on credential-unavailable rejections.
const (
	providerStatic           = "static"
	providerWorkloadIdentity = "workload_identity"
)

// AWSAuth is the transform.
type AWSAuth struct {
	logger           *slog.Logger
	rules            []hostmatch.Rule
	allowedRegions   map[string]struct{} // nil → allow any
	allowedServices  map[string]struct{} // nil → allow any
	creds            aws.CredentialsProvider
	unsignedPayload  bool
	allowChunkedBody bool

	// placeholderAccessKeyID, when set, turns on the write policy.
	placeholderAccessKeyID string

	now  func() time.Time
	sign signFunc
}

// credsKind reports which kind of provider backs the transform, for telemetry.
func (a *AWSAuth) credsKind() string {
	if _, ok := a.creds.(*staticSourceProvider); ok {
		return providerStatic
	}
	return providerWorkloadIdentity
}

func factory(cfg yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c config
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing aws_auth config: %w", err)
	}
	return newFromConfig(c, logger, secrets.BuildSource, BuildCredentialsProvider)
}

func newFromConfig(c config, logger *slog.Logger, build sourceBuilder, buildCreds credentialsProviderBuilder) (*AWSAuth, error) {
	hasStatic := !c.AccessKeyID.IsZero() || !c.SecretAccessKey.IsZero()
	hasProvider := !c.CredentialsProvider.IsZero()
	if hasStatic && hasProvider {
		return nil, fmt.Errorf("aws_auth: set either access_key_id/secret_access_key or credentials_provider, not both")
	}
	if !hasStatic && !hasProvider {
		return nil, fmt.Errorf("aws_auth: requires either access_key_id+secret_access_key or credentials_provider")
	}

	var creds aws.CredentialsProvider
	if hasProvider {
		p, err := buildCreds(c.CredentialsProvider, logger)
		if err != nil {
			return nil, fmt.Errorf("aws_auth: building credentials_provider: %w", err)
		}
		creds = p
	} else {
		if c.AccessKeyID.IsZero() {
			return nil, fmt.Errorf("aws_auth: access_key_id is required")
		}
		if c.SecretAccessKey.IsZero() {
			return nil, fmt.Errorf("aws_auth: secret_access_key is required")
		}
		accessKey, err := build(c.AccessKeyID, logger)
		if err != nil {
			return nil, fmt.Errorf("aws_auth: building access_key_id source: %w", err)
		}
		secretKey, err := build(c.SecretAccessKey, logger)
		if err != nil {
			return nil, fmt.Errorf("aws_auth: building secret_access_key source: %w", err)
		}
		creds = &staticSourceProvider{accessKey: accessKey, secretKey: secretKey}
	}

	rules, err := hostmatch.CompileRulesAllowRequireTLS(c.Rules, "aws_auth")
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("aws_auth: at least one entry in \"rules\" is required")
	}

	signer := v4.NewSigner()
	return &AWSAuth{
		logger:           logger,
		rules:            rules,
		allowedRegions:   buildAllowSet(c.AllowedRegions),
		allowedServices:  buildAllowSet(c.AllowedServices),
		creds:            creds,
		unsignedPayload:  c.UnsignedPayload,
		allowChunkedBody: c.AllowChunkedBody,

		placeholderAccessKeyID: c.PlaceholderAccessKeyID,

		now: time.Now,
		sign: func(ctx context.Context, creds aws.Credentials, req *http.Request, payloadHash, service, region string, signingTime time.Time) error {
			return signer.SignHTTP(ctx, creds, req, payloadHash, service, region, signingTime)
		},
	}, nil
}

// staticSourceProvider adapts two secrets.Source values into an
// aws.CredentialsProvider. The sources do their own TTL caching.
type staticSourceProvider struct {
	accessKey secrets.Source
	secretKey secrets.Source
}

func (p *staticSourceProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	ak, err := p.accessKey.Get(ctx)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("access_key_id: %w", err)
	}
	sk, err := p.secretKey.Get(ctx)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("secret_access_key: %w", err)
	}
	return aws.Credentials{
		AccessKeyID:     ak,
		SecretAccessKey: sk,
		Source:          "iron-proxy aws_auth static",
	}, nil
}

func buildAllowSet(items []string) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(items))
	for _, v := range items {
		if v == "" {
			continue
		}
		out[v] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (a *AWSAuth) Name() string { return "aws_auth" }

func (a *AWSAuth) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	// The proxy replays request transforms against a synthetic CONNECT request
	// to make tunnel-level policy decisions before MITM (see proxy.tunnelTransformCheck).
	// A CONNECT carries no SigV4 signature — the signed request only becomes
	// visible after the tunnel is established and TLS is terminated. Rejecting
	// it here would kill the tunnel before the real request is ever seen, so let
	// CONNECT pass; signing happens on the post-MITM request that follows.
	if req.Method == http.MethodConnect {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	// A connection the proxy does not decrypt (sni-only mode, or a host left
	// out of tls.intercept) reaches the pipeline as a host-only stand-in
	// request. There is nothing to sign and nothing to see, so let it pass:
	// rejecting it would make any host under these rules impossible to
	// tunnel. Whatever the client signed goes upstream unchanged.
	if tctx.Mode == transform.ModeSNIOnly {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	if !hostmatch.MatchAnyRule(a.rules, req) {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	if a.placeholderAccessKeyID != "" {
		resign, result := a.writePolicy(tctx, req)
		if !resign {
			return result, nil
		}
	}

	scope, err := parseInboundScope(req)
	if err != nil {
		tctx.Annotate("rejected", "missing_sigv4")
		tctx.Annotate("error", err.Error())
		return &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusBadRequest, "missing_sigv4"),
		}, nil
	}

	if a.allowedRegions != nil {
		if _, ok := a.allowedRegions[scope.region]; !ok {
			tctx.Annotate("rejected", "region_not_allowed")
			tctx.Annotate("region", scope.region)
			return &transform.TransformResult{
				Action:   transform.ActionReject,
				Response: errorResponse(req, http.StatusForbidden, "region_not_allowed"),
			}, nil
		}
	}
	if a.allowedServices != nil {
		if _, ok := a.allowedServices[scope.service]; !ok {
			tctx.Annotate("rejected", "service_not_allowed")
			tctx.Annotate("service", scope.service)
			return &transform.TransformResult{
				Action:   transform.ActionReject,
				Response: errorResponse(req, http.StatusForbidden, "service_not_allowed"),
			}, nil
		}
	}

	creds, err := a.creds.Retrieve(ctx)
	if err != nil {
		return a.rejectCredentialUnavailable(tctx, req, a.credsKind(), err), nil
	}

	payloadHash, reject := a.payloadHash(tctx, req)
	if reject != nil {
		return reject, nil
	}

	// Strip the inbound placeholder signature so SignHTTP produces a fresh,
	// untainted signature using only the headers we want signed.
	stripInboundSignatureHeaders(req)
	// X-Amz-Content-Sha256 is required by S3 and signed when present; setting
	// it explicitly makes the signed canonical request deterministic across
	// services.
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	if err := a.sign(ctx, creds, req, payloadHash, scope.service, scope.region, a.now()); err != nil {
		tctx.Annotate("rejected", "signing_failed")
		tctx.Annotate("error", err.Error())
		return &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusInternalServerError, "signing_failed"),
		}, nil
	}

	injected := []string{"header:Authorization", "header:X-Amz-Date", "header:X-Amz-Content-Sha256"}
	if creds.SessionToken != "" {
		injected = append(injected, "header:X-Amz-Security-Token")
	}
	tctx.Annotate("injected", injected)
	tctx.Annotate("service", scope.service)
	tctx.Annotate("region", scope.region)
	tctx.MarkCredentialInjected("aws_auth")
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// writePolicy decides, when placeholder_access_key_id is set, what happens
// to a request on a matched AWS host. The rule is: anything that writes to
// AWS must carry a credential the proxy holds; reads may carry anything.
//
//	signed with the placeholder key (Authorization header)  -> re-sign it
//	presigned with the placeholder key (query string)        -> reject: not supported yet
//	anything else (unsigned, Basic auth, another key):
//	  GET / HEAD / OPTIONS                                   -> pass untouched
//	  write, and an earlier transform injected a credential  -> pass untouched
//	  write, nothing injected                                -> reject
//
// "Anything else" covers, for example, the ECR registry's Basic auth (its
// token is swapped in by credential_mask, which marks the request) and the
// layer downloads ECR redirects to, presigned by AWS itself. A write the
// proxy did not authorize is the exfiltration case: the client's own AWS
// keys or presigned URL, or an unsigned POST to an API Gateway or load
// balancer someone else runs on amazonaws.com.
//
// The injected-credential check depends on pipeline order: transforms that
// swap credentials (credential_mask) must run before aws_auth. In the wrong
// order the write is rejected, which is the safe direction.
//
// resign=true means continue to the normal re-sign path. Otherwise result
// is what the transform returns.
func (a *AWSAuth) writePolicy(tctx *transform.TransformContext, req *http.Request) (bool, *transform.TransformResult) {
	if auth := req.Header.Get("Authorization"); strings.HasPrefix(auth, sigV4Algorithm+" ") {
		if scope, err := parseAuthHeaderScope(auth); err == nil && scope.accessKeyID == a.placeholderAccessKeyID {
			return true, nil
		}
	}
	if cred := req.URL.Query().Get("X-Amz-Credential"); cred != "" {
		if scope, err := parseCredentialPath(cred); err == nil && scope.accessKeyID == a.placeholderAccessKeyID {
			// Re-signing a presigned URL means signing again in the query
			// string, which this transform does not do. Fail loudly rather
			// than send a URL that cannot work.
			tctx.Annotate("rejected", "presigned_placeholder_not_supported")
			return false, &transform.TransformResult{
				Action:   transform.ActionReject,
				Response: errorResponse(req, http.StatusBadRequest, "presigned_placeholder_not_supported"),
			}
		}
	}

	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		tctx.Annotate("passthrough", "read_not_signed_by_proxy")
		return false, &transform.TransformResult{Action: transform.ActionContinue}
	}

	if injectedBy := tctx.CredentialsInjectedBy(); len(injectedBy) > 0 {
		tctx.Annotate("passthrough", "write_with_proxy_credential")
		tctx.Annotate("credential_injected_by", injectedBy)
		return false, &transform.TransformResult{Action: transform.ActionContinue}
	}

	tctx.Annotate("rejected", "write_not_signed_by_proxy")
	return false, &transform.TransformResult{
		Action:   transform.ActionReject,
		Response: errorResponse(req, http.StatusForbidden, "write_not_signed_by_proxy"),
	}
}

func (a *AWSAuth) TransformResponse(context.Context, *transform.TransformContext, *http.Request, *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// credentialScope is the access key ID and (region, service) pair extracted
// from an inbound SigV4 signature. The access key ID is the public half of
// the signing key: it says who signed, without revealing the secret.
type credentialScope struct {
	accessKeyID string
	region      string
	service     string
}

var errNoSigV4 = errors.New("request has no SigV4 signature (no Authorization header or X-Amz-Credential query param)")

// parseInboundScope extracts the credential scope from an inbound SigV4
// signature. Normal requests carry the scope in the Authorization header;
// pre-signed URLs carry it in the X-Amz-Credential query param.
func parseInboundScope(req *http.Request) (credentialScope, error) {
	if auth := req.Header.Get("Authorization"); auth != "" {
		return parseAuthHeaderScope(auth)
	}
	if cred := req.URL.Query().Get("X-Amz-Credential"); cred != "" {
		return parseCredentialPath(cred)
	}
	return credentialScope{}, errNoSigV4
}

// parseAuthHeaderScope pulls the Credential= field out of a SigV4
// Authorization header.
func parseAuthHeaderScope(auth string) (credentialScope, error) {
	rest, ok := strings.CutPrefix(auth, sigV4Algorithm+" ")
	if !ok {
		return credentialScope{}, fmt.Errorf("not a %s Authorization header", sigV4Algorithm)
	}
	for _, part := range strings.Split(rest, ",") {
		part = strings.TrimSpace(part)
		if cred, ok := strings.CutPrefix(part, "Credential="); ok {
			return parseCredentialPath(cred)
		}
	}
	return credentialScope{}, errors.New("missing Credential field in Authorization header")
}

// parseCredentialPath parses ACCESSKEY/DATE/REGION/SERVICE/aws4_request.
func parseCredentialPath(cred string) (credentialScope, error) {
	parts := strings.Split(cred, "/")
	if len(parts) != 5 {
		return credentialScope{}, fmt.Errorf("malformed credential scope %q: expected 5 path segments, got %d", cred, len(parts))
	}
	if parts[4] != "aws4_request" {
		return credentialScope{}, fmt.Errorf("malformed credential scope %q: expected aws4_request terminator", cred)
	}
	if parts[2] == "" || parts[3] == "" {
		return credentialScope{}, fmt.Errorf("malformed credential scope %q: empty region or service", cred)
	}
	return credentialScope{accessKeyID: parts[0], region: parts[2], service: parts[3]}, nil
}

// stripInboundSignatureHeaders removes every header SignHTTP is going to
// rewrite. Leaving the placeholder Authorization header in place would cause
// the SDK signer to include it in the canonical request, which produces a
// signature the upstream cannot verify.
func stripInboundSignatureHeaders(req *http.Request) {
	req.Header.Del("Authorization")
	req.Header.Del("X-Amz-Date")
	req.Header.Del("X-Amz-Security-Token")
	req.Header.Del("X-Amz-Content-Sha256")
}

// payloadHash returns the client's own declared mode when that mode leaves
// the body unsigned, otherwise the UNSIGNED-PAYLOAD sentinel when
// unsigned_payload is set, otherwise the SHA-256 hex hash of the request
// body. It reuses hmac_sign's body-verification policy: a truncated body or
// (by default) a chunked body produces a clean proxy-side rejection rather
// than a request the upstream will reject with an opaque "signature
// mismatch" error, or accept with part of the body missing.
func (a *AWSAuth) payloadHash(tctx *transform.TransformContext, req *http.Request) (string, *transform.TransformResult) {
	// Keep the client's payload mode when the body is not part of the
	// signature. Current AWS SDKs send S3 uploads as aws-chunked bodies with
	// a checksum trailer, declared as STREAMING-UNSIGNED-PAYLOAD-TRAILER, and
	// with no length known up front. Hashing that body here would buffer the
	// whole upload, fail on the missing length, and replace the declared mode
	// with one S3 rejects for an aws-chunked body. S3 checks the trailer
	// checksum itself, so the body is left unread. This runs before the
	// unsigned_payload setting: replacing the trailer mode with
	// UNSIGNED-PAYLOAD is just as invalid for an aws-chunked body. A declared
	// hex hash still takes the paths below: an earlier transform may have
	// rewritten the body, and the hash must match what is actually sent.
	declared := req.Header.Get("X-Amz-Content-Sha256")
	switch {
	case declared == streamingUnsignedPayloadTrailer || declared == unsignedPayload:
		if reject := a.checkAlreadyBufferedBody(tctx, req); reject != nil {
			return "", reject
		}
		tctx.Annotate("payload", declared)
		return declared, nil
	case strings.HasPrefix(declared, "STREAMING-"):
		// The other STREAMING-* modes sign the body as it streams:
		// STREAMING-AWS4-HMAC-SHA256-PAYLOAD and its TRAILER and ECDSA variants
		// sign every chunk, and STREAMING-AWS4-HMAC-SHA256-EVENTS signs every
		// event-stream message (Transcribe streaming, Lex, Bedrock
		// bidirectional streams). Each signature is chained from the request
		// signature and made with the client's key, so re-signing only the
		// headers can never produce a request upstream accepts.
		tctx.Annotate("rejected", "signed_streaming_payload_not_supported")
		tctx.Annotate("payload", streamingModeLabel(declared))
		return "", &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusBadRequest, "signed_streaming_payload_not_supported"),
		}
	}

	if a.unsignedPayload {
		if reject := a.checkAlreadyBufferedBody(tctx, req); reject != nil {
			return "", reject
		}
		return unsignedPayload, nil
	}

	if req.Body == nil || req.Body == http.NoBody {
		if req.ContentLength > 0 {
			tctx.Annotate("rejected", "body_missing")
			tctx.Annotate("content_length", req.ContentLength)
			return "", &transform.TransformResult{
				Action:   transform.ActionReject,
				Response: errorResponse(req, http.StatusBadRequest, "body_missing"),
			}
		}
		return emptyPayloadSHA256, nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		tctx.Annotate("rejected", "body_read_failed")
		tctx.Annotate("error", err.Error())
		return "", &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusBadRequest, "body_read_failed"),
		}
	}

	switch {
	case req.ContentLength >= 0 && int64(len(body)) < req.ContentLength:
		tctx.Annotate("rejected", "body_truncated")
		tctx.Annotate("content_length", req.ContentLength)
		tctx.Annotate("buffered_length", len(body))
		return "", &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusRequestEntityTooLarge, "body_truncated"),
		}
	case req.ContentLength < 0 && !a.allowChunkedBody:
		tctx.Annotate("rejected", "chunked_body_not_allowed")
		return "", &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusBadRequest, "chunked_body_not_allowed"),
		}
	case req.ContentLength < 0 && a.allowChunkedBody:
		a.logger.Warn("aws_auth signing chunked request body without length verification",
			"host", hostmatch.StripPort(req.Host),
			"path", req.URL.Path,
			"buffered_length", len(body),
		)
	}

	req.Body = transform.NewBufferedBodyFromBytes(body)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

func (a *AWSAuth) rejectCredentialUnavailable(tctx *transform.TransformContext, req *http.Request, which string, err error) *transform.TransformResult {
	tctx.Annotate("rejected", "credential_unavailable")
	tctx.Annotate("credential", which)
	tctx.Annotate("error", err.Error())
	return &transform.TransformResult{
		Action:   transform.ActionReject,
		Response: errorResponse(req, http.StatusBadGateway, "credential_unavailable"),
	}
}

// checkAlreadyBufferedBody guards the paths that sign without reading the
// body. An unread body is streamed upstream in full, so nothing needs
// checking. But if an earlier transform read it (body_capture, or secrets
// matching in the body), BufferedBody kept only the first
// max_request_body_bytes and closed the original, and the proxy will send that
// prefix. Apply the same checks as the hashing path: a body shorter than its
// Content-Length is refused, and a chunked body, whose truncation cannot be
// detected, is refused unless allow_chunked_body is set. Returns nil to
// continue.
func (a *AWSAuth) checkAlreadyBufferedBody(tctx *transform.TransformContext, req *http.Request) *transform.TransformResult {
	buffered, ok := req.Body.(*transform.BufferedBody)
	if !ok || buffered.Len() < 0 {
		return nil
	}
	switch {
	case req.ContentLength >= 0 && int64(buffered.Len()) < req.ContentLength:
		tctx.Annotate("rejected", "body_truncated")
		tctx.Annotate("content_length", req.ContentLength)
		tctx.Annotate("buffered_length", buffered.Len())
		return &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusRequestEntityTooLarge, "body_truncated"),
		}
	case req.ContentLength < 0 && !a.allowChunkedBody:
		tctx.Annotate("rejected", "chunked_body_not_allowed")
		tctx.Annotate("buffered_length", buffered.Len())
		return &transform.TransformResult{
			Action:   transform.ActionReject,
			Response: errorResponse(req, http.StatusBadRequest, "chunked_body_not_allowed"),
		}
	}
	return nil
}

// knownStreamingModes are the body-signing STREAMING-* payload modes AWS
// defines. They are refused, and named in the audit log.
var knownStreamingModes = map[string]bool{
	"STREAMING-AWS4-HMAC-SHA256-PAYLOAD":               true,
	"STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER":       true,
	"STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD":         true,
	"STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER": true,
	"STREAMING-AWS4-HMAC-SHA256-EVENTS":                true,
}

// streamingModeLabel returns what the audit log records for a refused
// STREAMING-* value: the mode's name if it is one AWS defines, otherwise a
// fixed label. The header value itself is never logged: it is client
// controlled, and an earlier transform (secrets matching all headers) may
// have swapped a real secret into it.
func streamingModeLabel(declared string) string {
	if knownStreamingModes[declared] {
		return declared
	}
	return "unrecognised_streaming_mode"
}

func errorResponse(req *http.Request, status int, reason string) *http.Response {
	body := []byte(`{"error":"aws_auth","reason":"` + reason + `"}`)
	return &http.Response{
		StatusCode:    status,
		Status:        strconv.Itoa(status) + " " + http.StatusText(status),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          transform.NewBufferedBodyFromBytes(body),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}
