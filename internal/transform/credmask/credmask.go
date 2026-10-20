// Package credmask implements a transform that keeps durable credentials off
// the client by masking them at birth and swapping them back on the way out.
//
// It is the native Go port of the Cryptex mitmproxy addons
// (github_tokenize.py, oauth_refresh_tokenize.py, vault.py in
// cryptex-dev-sandbox), plus the Amazon ECR registry token. Three credential
// families are handled:
//
// GitHub OAuth tokens (gho_/ghu_/ghs_/ghr_/ghp_):
//
//  1. Issuance (response). `gh auth login` polls
//     POST github.com/login/oauth/access_token. When the response carries a
//     real token, the real value goes into the store and the client gets a
//     same-shape mask instead.
//  2. Consumption (request headers only). Later requests carry the mask in
//     Authorization (`token <mask>`, `Bearer <mask>`, or Basic auth with the
//     mask as the password, as git-over-HTTPS does). The mask is swapped for
//     the real token before the request goes upstream. Only headers are
//     touched, so large request bodies (a big `git push`) still stream, and
//     responses are not read: the real token exists only in this store and
//     at GitHub, so nothing the client could have written can contain it,
//     and GitHub does not reflect the Authorization header back.
//  3. Refresh (request). GitHub App user tokens expire and are refreshed
//     by POSTing the refresh_token (masked at issuance, step 1) back to the
//     issuance endpoint. The mask is swapped for the real refresh token in
//     the query string or a form/JSON body, inside TLS only.
//
// OAuth refresh tokens (Claude, Codex), configured per provider:
//
//   - Response: a real refresh_token in the JSON body is masked. Covers first
//     issuance and every rotated token on refresh.
//   - Request: a masked refresh_token in the JSON body is swapped back for
//     the real value before the refresh goes upstream.
//
// Amazon ECR registry token:
//
//   - Response: GetAuthorizationToken (`aws ecr get-login-password`, the
//     docker credential helper) returns base64("AWS:<token>"). The token is
//     masked and the pair re-encoded.
//   - Request: the registry (<account>.dkr.ecr.<region>.amazonaws.com) gets
//     Basic auth AWS:<mask>; the mask is swapped for the real token.
//
// Every swap also calls tctx.MarkCredentialInjected, so a later transform
// (aws_auth's write policy) can tell a request carrying a proxy-held
// credential from one the client authorized on its own. This transform only
// masks and swaps; it never decides whether a request may go out.
//
// Fail posture (same as the Python addons):
//
//   - Masking (responses): if a real credential cannot be masked, the
//     response is REPLACED with a 500 so the login/refresh fails loudly. A
//     real credential never reaches the client. That includes a JSON token
//     response that does not parse: it may have been cut short by
//     proxy.max_response_body_bytes with the real token still in it.
//   - Swapping (requests): if the store errors, the mask is left in place.
//     It goes upstream, earns a clean 401, and nothing leaks.
//   - Swapping happens only inside TLS. Every rule that swaps a real
//     credential in is compiled with require_tls, whatever the config says,
//     so a plain-HTTP request keeps its mask and a real credential is never
//     sent in clear text. Masking (responses) still runs on plain HTTP: it is
//     the safe direction.
//
// iron-proxy never decompresses bodies, so this transform asks for
// Accept-Encoding: identity on the issuance/refresh requests whose responses
// it must read, and decodes gzip itself if upstream sends it anyway. A body
// in any other encoding on an issuance/refresh endpoint fails closed.
//
// Example config:
//
//	transforms:
//	  - name: credential_mask
//	    config:
//	      store_dir: /var/lib/iron-proxy/credmask
//	      enforce_source: true
//	      # Every kind below is the label stored on a mask. Each must be
//	      # unique across the whole config; renaming one orphans its masks.
//	      github:
//	        access_token_kind: "github:access_token"
//	        refresh_token_kind: "github:refresh_token"
//	        consume_rules:
//	          - host: github.com
//	          - host: api.github.com
//	        issue_rules:
//	          - host: github.com
//	            methods: [POST]
//	            paths: [/login/oauth/access_token]
//	      oauth_refresh:
//	        - kind: "claude:refresh"
//	          mask_prefix: "sk-ant-ort01-"
//	          rules:
//	            - host: platform.claude.com
//	              methods: [POST]
//	              paths: [/v1/oauth/token]
//	        - kind: "codex:refresh"
//	          mask_prefix: "rt.1."
//	          rules:
//	            # Whole host, as the Python addon did: Codex uses more than
//	            # one token path (/oauth/token and a deviceauth endpoint).
//	            - host: auth.openai.com
//	              methods: [POST]
//	      ecr:
//	        token_kind: "ecr:token"
//	        issue_rules:
//	          - host: api.ecr.af-south-1.amazonaws.com
//	            methods: [POST]
//	        consume_rules:
//	          - host: "*.dkr.ecr.af-south-1.amazonaws.com"
package credmask

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("credential_mask", factory)
}

// githubTokenPrefixes are the token kinds gh issues.
var githubTokenPrefixes = []string{"gho_", "ghu_", "ghs_", "ghr_", "ghp_"}

// githubTokenFields are the issuance body fields that may hold a token.
var githubTokenFields = []string{"access_token", "refresh_token"}

// githubKindForField is the configured kind a GitHub issuance field is
// stored as.
func (m *CredMask) githubKindForField(field string) string {
	if field == "refresh_token" {
		return m.githubRefreshKind
	}
	return m.githubAccessKind
}

// tokenMaxDecodedBytes bounds a decoded login/refresh response. Real token
// responses are well under 1 KiB; anything larger than this aborts rather
// than being decompressed into memory.
const tokenMaxDecodedBytes = 1024 * 1024

// errDecodedTooLarge is returned by readDecodedBody when the decoded body, or
// the declared Content-Length, is over its limit.
var errDecodedTooLarge = errors.New("decoded body is over the size limit")

type config struct {
	StoreDir      string               `yaml:"store_dir"`
	EnforceSource *bool                `yaml:"enforce_source,omitempty"` // default true
	GitHub        *githubConfig        `yaml:"github,omitempty"`
	OAuthRefresh  []oauthRefreshConfig `yaml:"oauth_refresh,omitempty"`
	ECR           *ecrConfig           `yaml:"ecr,omitempty"`
}

// ecrConfig masks the Amazon ECR registry token. GetAuthorizationToken
// (issue_rules, the ECR API host) returns a 12-hour token that is the Basic
// auth password for the registry (consume_rules, the <account>.dkr.ecr
// host). The client gets a mask; the registry gets the real token.
type ecrConfig struct {
	TokenKind    string                 `yaml:"token_kind"`
	IssueRules   []hostmatch.RuleConfig `yaml:"issue_rules"`
	ConsumeRules []hostmatch.RuleConfig `yaml:"consume_rules"`
}

type githubConfig struct {
	// The kinds GitHub masks are stored as, like oauth_refresh's kind. Both
	// are required. Renaming one orphans the masks stored under the old name.
	AccessTokenKind  string                 `yaml:"access_token_kind"`
	RefreshTokenKind string                 `yaml:"refresh_token_kind"`
	ConsumeRules     []hostmatch.RuleConfig `yaml:"consume_rules"`
	IssueRules       []hostmatch.RuleConfig `yaml:"issue_rules"`
}

type oauthRefreshConfig struct {
	Kind       string                 `yaml:"kind"`
	Field      string                 `yaml:"field,omitempty"` // default refresh_token
	MaskPrefix string                 `yaml:"mask_prefix"`
	Rules      []hostmatch.RuleConfig `yaml:"rules"`
}

type oauthProvider struct {
	kind       string
	field      string
	maskPrefix string
	rules      []hostmatch.Rule // as configured: response masking
	swapRules  []hostmatch.Rule // require_tls forced on: request swap
}

// CredMask is the transform.
type CredMask struct {
	store         *Store
	enforceSource bool
	logger        *slog.Logger

	githubConsume []hostmatch.Rule // require_tls forced on; nil when github is not configured
	githubIssue   []hostmatch.Rule // as configured: response masking
	githubRefresh []hostmatch.Rule // issue rules with require_tls forced on: refresh_token swap

	// githubAccessKind is the only kind swapped into an Authorization header:
	// a masked GitHub access token. A GitHub refresh token, or another
	// provider's credential, is never sent there. githubRefreshKind is the
	// kind swapped back into a GitHub token refresh. Both come from config.
	githubAccessKind  string
	githubRefreshKind string

	oauth []oauthProvider

	ecrIssue   []hostmatch.Rule // as configured: response masking; nil when ecr is not configured
	ecrConsume []hostmatch.Rule // require_tls forced on: Basic-auth swap to the registry
	ecrKind    string
}

func factory(node yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c config
	if err := node.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing credential_mask config: %w", err)
	}
	if c.StoreDir == "" {
		return nil, errors.New("credential_mask: store_dir is required")
	}
	// Fail loud at load if the store is unavailable: running without it
	// would either leak real tokens (issuance) or break all auth (consume).
	store, err := OpenShared(c.StoreDir)
	if err != nil {
		return nil, fmt.Errorf("credential_mask: %w", err)
	}
	return newFromConfig(c, store, logger)
}

func newFromConfig(c config, store *Store, logger *slog.Logger) (*CredMask, error) {
	if logger == nil {
		logger = slog.Default()
	}
	m := &CredMask{
		store:         store,
		enforceSource: c.EnforceSource == nil || *c.EnforceSource,
		logger:        logger,
	}

	// A mask resolves only as its own kind, so every kind in the config must
	// be unique: two providers sharing one would let one provider's mask
	// resolve at the other's endpoint and send the real credential there.
	// kindsInUse maps each kind to where it was configured.
	kindsInUse := map[string]string{}
	addKind := func(kind, where string) error {
		if kind == "" {
			return fmt.Errorf("credential_mask %s is required", where)
		}
		if owner, dup := kindsInUse[kind]; dup {
			return fmt.Errorf("credential_mask %s: kind %q is already used by %s; every kind must be unique", where, kind, owner)
		}
		kindsInUse[kind] = where
		return nil
	}

	if c.GitHub != nil {
		if len(c.GitHub.ConsumeRules) == 0 || len(c.GitHub.IssueRules) == 0 {
			return nil, errors.New("credential_mask: github needs both consume_rules and issue_rules")
		}
		if err := addKind(c.GitHub.AccessTokenKind, "github.access_token_kind"); err != nil {
			return nil, err
		}
		if err := addKind(c.GitHub.RefreshTokenKind, "github.refresh_token_kind"); err != nil {
			return nil, err
		}
		m.githubAccessKind = c.GitHub.AccessTokenKind
		m.githubRefreshKind = c.GitHub.RefreshTokenKind
		var err error
		if m.githubConsume, err = hostmatch.CompileRulesAllowRequireTLS(withRequireTLS(c.GitHub.ConsumeRules), "credential_mask github.consume_rules"); err != nil {
			return nil, err
		}
		if m.githubIssue, err = hostmatch.CompileRules(c.GitHub.IssueRules, "credential_mask github.issue_rules"); err != nil {
			return nil, err
		}
		if m.githubRefresh, err = hostmatch.CompileRulesAllowRequireTLS(withRequireTLS(c.GitHub.IssueRules), "credential_mask github.issue_rules"); err != nil {
			return nil, err
		}
	}

	for i, p := range c.OAuthRefresh {
		ctx := fmt.Sprintf("credential_mask oauth_refresh[%d]", i)
		if err := addKind(p.Kind, fmt.Sprintf("oauth_refresh[%d].kind", i)); err != nil {
			return nil, err
		}
		if p.MaskPrefix == "" {
			return nil, fmt.Errorf("%s: mask_prefix is required", ctx)
		}
		if len(p.Rules) == 0 {
			return nil, fmt.Errorf("%s: rules are required", ctx)
		}
		rules, err := hostmatch.CompileRules(p.Rules, ctx)
		if err != nil {
			return nil, err
		}
		swapRules, err := hostmatch.CompileRulesAllowRequireTLS(withRequireTLS(p.Rules), ctx)
		if err != nil {
			return nil, err
		}
		field := p.Field
		if field == "" {
			field = "refresh_token"
		}
		m.oauth = append(m.oauth, oauthProvider{kind: p.Kind, field: field, maskPrefix: p.MaskPrefix, rules: rules, swapRules: swapRules})
	}

	if c.ECR != nil {
		if len(c.ECR.IssueRules) == 0 || len(c.ECR.ConsumeRules) == 0 {
			return nil, errors.New("credential_mask: ecr needs both issue_rules and consume_rules")
		}
		if err := addKind(c.ECR.TokenKind, "ecr.token_kind"); err != nil {
			return nil, err
		}
		m.ecrKind = c.ECR.TokenKind
		var err error
		if m.ecrIssue, err = hostmatch.CompileRules(c.ECR.IssueRules, "credential_mask ecr.issue_rules"); err != nil {
			return nil, err
		}
		if m.ecrConsume, err = hostmatch.CompileRulesAllowRequireTLS(withRequireTLS(c.ECR.ConsumeRules), "credential_mask ecr.consume_rules"); err != nil {
			return nil, err
		}
	}

	if m.githubConsume == nil && len(m.oauth) == 0 && m.ecrIssue == nil {
		return nil, errors.New("credential_mask: configure github, oauth_refresh and/or ecr")
	}
	return m, nil
}

// withRequireTLS returns a copy of rules with require_tls forced on. Every
// rule that swaps a real credential into a request goes through it, so the
// guard cannot be configured away.
func withRequireTLS(rules []hostmatch.RuleConfig) []hostmatch.RuleConfig {
	out := make([]hostmatch.RuleConfig, len(rules))
	for i, rc := range rules {
		rc.RequireTLS = true
		out[i] = rc
	}
	return out
}

func (m *CredMask) Name() string { return "credential_mask" }

// sourceOf is the client identity a mask is bound to: the client's IP.
func sourceOf(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

func (m *CredMask) matchingOAuth(req *http.Request) *oauthProvider {
	for i := range m.oauth {
		if hostmatch.MatchAnyRule(m.oauth[i].rules, req) {
			return &m.oauth[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Request side
// ---------------------------------------------------------------------------

func (m *CredMask) TransformRequest(_ context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	cont := &transform.TransformResult{Action: transform.ActionContinue}

	if m.githubConsume != nil && hostmatch.MatchAnyRule(m.githubIssue, req) {
		// We must read the issuance response, so ask for it uncompressed.
		req.Header.Set("Accept-Encoding", "identity")
	}

	if m.githubConsume != nil && hostmatch.MatchAnyRule(m.githubRefresh, req) {
		if err := m.swapGitHubRefresh(tctx, req); err != nil {
			return nil, err
		}
	}

	if m.githubConsume != nil && hostmatch.MatchAnyRule(m.githubConsume, req) {
		m.swapGitHubAuth(tctx, req)
	}

	if p := m.matchingOAuth(req); p != nil {
		// Asked for uncompressed on plain HTTP too: the response is still masked.
		req.Header.Set("Accept-Encoding", "identity")
		if hostmatch.MatchAnyRule(p.swapRules, req) {
			if err := m.swapOAuthRefresh(tctx, req, p); err != nil {
				return nil, err
			}
		}
	}

	if m.ecrIssue != nil && hostmatch.MatchAnyRule(m.ecrIssue, req) && isECRGetAuthorizationToken(req) {
		// We must read the token response, so ask for it uncompressed.
		req.Header.Set("Accept-Encoding", "identity")
	}

	if m.ecrConsume != nil && hostmatch.MatchAnyRule(m.ecrConsume, req) {
		m.swapECRAuth(tctx, req)
	}

	return cont, nil
}

// isECRGetAuthorizationToken reports whether req is an ECR
// GetAuthorizationToken call. The ECR API is JSON-RPC: every operation is a
// POST to the same path, named in X-Amz-Target
// (AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken). Matched on
// the operation suffix so an API version bump still masks the token.
func isECRGetAuthorizationToken(req *http.Request) bool {
	return req.Method == http.MethodPost &&
		strings.HasSuffix(req.Header.Get("X-Amz-Target"), ".GetAuthorizationToken")
}

// swapECRAuth replaces a masked ECR token in a registry request's Basic
// auth (user "AWS", password = the token) with the real token. Headers
// only, so a large `docker push` layer upload still streams.
func (m *CredMask) swapECRAuth(tctx *transform.TransformContext, req *http.Request) {
	auth := req.Header.Get("Authorization")
	scheme, value, ok := strings.Cut(auth, " ")
	if !ok || !strings.EqualFold(scheme, "basic") {
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return
	}
	user, pw, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return
	}
	real, found, err := m.store.Resolve(pw, m.ecrKind, sourceOf(req), m.enforceSource)
	if err != nil {
		// Fail safe: leave the mask; the registry answers 401, nothing leaks.
		m.logger.Error("credential_mask: store error resolving ecr mask, header left unchanged", slog.String("error", err.Error()))
		tctx.Annotate("resolve_error", m.ecrKind)
		return
	}
	if !found {
		return
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+real)))
	tctx.Annotate("swapped", m.ecrKind)
	tctx.MarkCredentialInjected("credential_mask")
}

// swapGitHubAuth replaces a mask in the Authorization header with the real
// token. Headers only: the body is never read, so large uploads stream.
func (m *CredMask) swapGitHubAuth(tctx *transform.TransformContext, req *http.Request) {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		return
	}
	scheme, value, ok := strings.Cut(auth, " ")
	if !ok {
		return
	}
	value = strings.TrimSpace(value)
	source := sourceOf(req)

	var newAuth string
	switch strings.ToLower(scheme) {
	case "token", "bearer":
		real, found, err := m.store.Resolve(value, m.githubAccessKind, source, m.enforceSource)
		if err != nil {
			// Fail safe: leave the mask; upstream answers 401, nothing leaks.
			m.logger.Error("credential_mask: store error resolving github mask, header left unchanged", slog.String("error", err.Error()))
			tctx.Annotate("resolve_error", "github")
			return
		}
		if !found {
			return
		}
		newAuth = scheme + " " + real

	case "basic":
		// git-over-HTTPS sends the token as the Basic-auth password.
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return
		}
		user, pw, ok := strings.Cut(string(decoded), ":")
		if !ok {
			return
		}
		real, found, err := m.store.Resolve(pw, m.githubAccessKind, source, m.enforceSource)
		if err != nil {
			m.logger.Error("credential_mask: store error resolving github basic-auth mask, header left unchanged", slog.String("error", err.Error()))
			tctx.Annotate("resolve_error", "github")
			return
		}
		if !found {
			return
		}
		newAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+real))

	default:
		return
	}

	req.Header.Set("Authorization", newAuth)
	tctx.Annotate("swapped", "github:authorization")
	tctx.MarkCredentialInjected("credential_mask")
}

// swapOAuthRefresh replaces a masked refresh token in a JSON request body.
//
// The only error returned is a failed read of the client's body: the request
// must then fail (502) rather than go upstream with part of its body.
func (m *CredMask) swapOAuthRefresh(tctx *transform.TransformContext, req *http.Request, p *oauthProvider) error {
	data, ok, err := readRefreshRequestBody(req)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	obj, ok := parseJSONObject(data)
	if !ok {
		return nil
	}
	val, ok := obj[p.field].(string)
	if !ok || val == "" {
		return nil
	}
	real, found, err := m.store.Resolve(val, p.kind, sourceOf(req), m.enforceSource)
	if err != nil {
		// Fail safe: leave the mask; the refresh is rejected and the user re-auths.
		m.logger.Error("credential_mask: store error resolving refresh mask, left unchanged",
			slog.String("kind", p.kind), slog.String("error", err.Error()))
		tctx.Annotate("resolve_error", p.kind)
		return nil
	}
	if !found {
		return nil
	}
	obj[p.field] = real
	out, err := encodeJSON(obj)
	if err != nil {
		m.logger.Error("credential_mask: re-encoding refresh request failed, left unchanged",
			slog.String("kind", p.kind), slog.String("error", err.Error()))
		return nil
	}
	replacement := transform.NewBufferedBodyFromBytes(out)
	replacement.MarkReplaced()
	req.Body = replacement
	req.ContentLength = int64(len(out))
	req.Header.Set("Content-Length", strconv.Itoa(len(out)))
	tctx.Annotate("swapped", p.kind)
	tctx.MarkCredentialInjected("credential_mask")
	return nil
}

// refreshRequestMaxBytes bounds a request body the refresh swaps will read.
// Real refresh requests are a few hundred bytes. A larger declared body is
// left alone, unread: reading it would make the pipeline's BufferedBody
// truncate it at proxy.max_request_body_bytes, and the cut body would be
// forwarded. The mask then goes upstream unswapped, which is the safe
// direction.
const refreshRequestMaxBytes = 1024 * 1024

// readRefreshRequestBody reads a request body for a refresh swap.
//
// ok=false means leave the request alone: no body, an empty body, a
// compressed body, or a declared Content-Length over refreshRequestMaxBytes
// (not read at all). A body of unknown length is read: refresh clients send
// a Content-Length.
//
// An error means the client's body failed mid-read. BufferedBody has already
// kept the part it got, so the caller must fail the request instead of
// forwarding a partial body.
func readRefreshRequestBody(req *http.Request) ([]byte, bool, error) {
	if req.Body == nil || !bodyIsUnencoded(req.Header) {
		return nil, false, nil
	}
	if req.ContentLength > refreshRequestMaxBytes {
		return nil, false, nil
	}
	data, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, false, fmt.Errorf("credential_mask: reading refresh request body: %w", err)
	}
	if len(data) == 0 {
		return nil, false, nil
	}
	return data, true, nil
}

// swapGitHubRefresh replaces a masked GitHub refresh token with the real one
// in a refresh request to the issuance endpoint. Without it, GitHub App user
// tokens (which expire) could never be refreshed through the proxy.
//
// GitHub documents the refresh_token as a query parameter
// (grant_type=refresh_token); clients also send it in a form or JSON body.
// All three are handled. The query is safe to rewrite: the audit log records
// the path only, never the query.
//
// The only error returned is a failed read of the client's body: the request
// must then fail (502) rather than go upstream with part of its body.
func (m *CredMask) swapGitHubRefresh(tctx *transform.TransformContext, req *http.Request) error {
	source := sourceOf(req)
	swapped := false

	// 1. Query string.
	query := req.URL.Query()
	if mask := query.Get("refresh_token"); mask != "" {
		real, found, err := m.store.Resolve(mask, m.githubRefreshKind, source, m.enforceSource)
		if err != nil {
			m.logger.Error("credential_mask: store error resolving github refresh mask in query, left unchanged", slog.String("error", err.Error()))
			tctx.Annotate("resolve_error", m.githubRefreshKind)
			return nil
		}
		if found {
			query.Set("refresh_token", real)
			req.URL.RawQuery = query.Encode()
			swapped = true
		}
	}

	// 2. Body: form-encoded or JSON.
	data, ok, err := readRefreshRequestBody(req)
	if err != nil {
		return err
	}
	if ok {
		out, bodySwapped, err := m.swapGitHubRefreshInBody(req.Header.Get("Content-Type"), data, source)
		if err != nil {
			m.logger.Error("credential_mask: swapping github refresh mask in body failed, left unchanged", slog.String("error", err.Error()))
			tctx.Annotate("resolve_error", m.githubRefreshKind)
			return nil
		}
		if bodySwapped {
			replacement := transform.NewBufferedBodyFromBytes(out)
			replacement.MarkReplaced()
			req.Body = replacement
			req.ContentLength = int64(len(out))
			req.Header.Set("Content-Length", strconv.Itoa(len(out)))
			swapped = true
		}
	}

	if swapped {
		tctx.Annotate("swapped", m.githubRefreshKind)
		tctx.MarkCredentialInjected("credential_mask")
	}
	return nil
}

// swapGitHubRefreshInBody returns the body with a masked refresh_token
// replaced by the real one. swapped=false means the body had no mask of
// ours and must be left as it was.
func (m *CredMask) swapGitHubRefreshInBody(contentType string, data []byte, source string) ([]byte, bool, error) {
	if strings.Contains(contentType, "application/json") || bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		obj, ok := parseJSONObject(data)
		if !ok {
			return nil, false, nil
		}
		mask, ok := obj["refresh_token"].(string)
		if !ok || mask == "" {
			return nil, false, nil
		}
		real, found, err := m.store.Resolve(mask, m.githubRefreshKind, source, m.enforceSource)
		if err != nil || !found {
			return nil, false, err
		}
		obj["refresh_token"] = real
		out, err := encodeJSON(obj)
		if err != nil {
			return nil, false, err
		}
		return out, true, nil
	}

	form, err := url.ParseQuery(string(data))
	if err != nil {
		return nil, false, nil
	}
	mask := form.Get("refresh_token")
	if mask == "" {
		return nil, false, nil
	}
	real, found, err := m.store.Resolve(mask, m.githubRefreshKind, source, m.enforceSource)
	if err != nil || !found {
		return nil, false, err
	}
	form.Set("refresh_token", real)
	return []byte(form.Encode()), true, nil
}

// ---------------------------------------------------------------------------
// Response side
// ---------------------------------------------------------------------------

func (m *CredMask) TransformResponse(_ context.Context, tctx *transform.TransformContext, req *http.Request, resp *http.Response) (*transform.TransformResult, error) {
	cont := &transform.TransformResult{Action: transform.ActionContinue}

	if m.githubConsume != nil && hostmatch.MatchAnyRule(m.githubIssue, req) {
		return m.maskGitHubIssuance(tctx, req, resp), nil
	}

	if p := m.matchingOAuth(req); p != nil {
		return m.maskOAuthRefresh(tctx, req, resp, p), nil
	}

	if m.ecrIssue != nil && hostmatch.MatchAnyRule(m.ecrIssue, req) && isECRGetAuthorizationToken(req) {
		return m.maskECRToken(tctx, req, resp), nil
	}

	return cont, nil
}

// maskECRToken masks every token in a GetAuthorizationToken response:
//
//	{"authorizationData":[{"authorizationToken":"<base64 of AWS:token>",
//	  "expiresAt":...,"proxyEndpoint":"https://<account>.dkr.ecr..."}]}
//
// Only the token after "AWS:" is masked, and the pair is re-encoded, so
// the client (aws ecr get-login-password, docker-credential-ecr-login)
// still decodes it into a user and password.
func (m *CredMask) maskECRToken(tctx *transform.TransformContext, req *http.Request, resp *http.Response) *transform.TransformResult {
	cont := &transform.TransformResult{Action: transform.ActionContinue}

	if resp.StatusCode != http.StatusOK {
		return cont // an error response carries no token
	}
	body, err := readDecodedBody(resp, tokenMaxDecodedBytes)
	if err != nil {
		return m.abort(tctx, req, m.ecrKind, fmt.Sprintf("cannot read token response: %v", err))
	}
	obj, ok := parseJSONObject(body)
	if !ok {
		// A 200 that does not parse may be cut short with the token still in it.
		return m.abort(tctx, req, m.ecrKind, "token response is not a JSON object (truncated?)")
	}
	entries, ok := obj["authorizationData"].([]any)
	if !ok {
		return m.abort(tctx, req, m.ecrKind, "token response has no authorizationData list")
	}

	source := sourceOf(req)
	for i, e := range entries {
		entry, ok := e.(map[string]any)
		if !ok {
			return m.abort(tctx, req, m.ecrKind, fmt.Sprintf("authorizationData[%d] is not an object", i))
		}
		encoded, ok := entry["authorizationToken"].(string)
		if !ok || encoded == "" {
			return m.abort(tctx, req, m.ecrKind, fmt.Sprintf("authorizationData[%d] has no authorizationToken", i))
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return m.abort(tctx, req, m.ecrKind, fmt.Sprintf("authorizationData[%d].authorizationToken is not base64", i))
		}
		user, token, ok := strings.Cut(string(decoded), ":")
		if !ok || token == "" {
			return m.abort(tctx, req, m.ecrKind, fmt.Sprintf("authorizationData[%d].authorizationToken is not user:token", i))
		}
		if m.store.IsMask(token) {
			continue // already a mask; never mask a mask
		}
		// The store keeps everything up to a token's last underscore as the
		// mask's prefix (GitHub's gho_ style). ECR tokens are base64 with no
		// underscore, so the whole token is randomised. If one ever had an
		// underscore, most of the real token would stay visible in the mask,
		// so refuse instead.
		if strings.Contains(token, "_") {
			return m.abort(tctx, req, m.ecrKind, fmt.Sprintf("authorizationData[%d] token has unexpected shape (underscore)", i))
		}
		mask, err := m.store.Tokenize(token, m.ecrKind, source, "")
		if err != nil {
			return m.abort(tctx, req, m.ecrKind, err.Error())
		}
		entry["authorizationToken"] = base64.StdEncoding.EncodeToString([]byte(user + ":" + mask))
	}

	out, err := encodeJSON(obj)
	if err != nil {
		return m.abort(tctx, req, m.ecrKind, err.Error())
	}
	setResponseBody(resp, out)
	m.logger.Info("credential_mask: masked ecr token in response", slog.Int("tokens", len(entries)))
	tctx.Annotate("masked", m.ecrKind)
	return cont
}

func (m *CredMask) maskGitHubIssuance(tctx *transform.TransformContext, req *http.Request, resp *http.Response) *transform.TransformResult {
	cont := &transform.TransformResult{Action: transform.ActionContinue}

	// The device flow answers 200 {"error":"authorization_pending"} while
	// waiting; only a 200 can carry a token.
	if resp.StatusCode != http.StatusOK {
		return cont
	}
	body, err := readDecodedBody(resp, tokenMaxDecodedBytes)
	if err != nil {
		return m.abort(tctx, req, "github:issue", fmt.Sprintf("cannot read issuance response: %v", err))
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return cont
	}

	source := sourceOf(req)
	ctype := resp.Header.Get("Content-Type")
	var out []byte
	changed := false

	if strings.Contains(ctype, "application/json") || bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		obj, ok := parseJSONObject(body)
		if !ok {
			return m.abort(tctx, req, "github:issue", "issuance response is not a JSON object")
		}
		for _, field := range githubTokenFields {
			val, ok := obj[field].(string)
			if !ok || val == "" {
				continue
			}
			if !hasAnyPrefix(val, githubTokenPrefixes) {
				// There IS a token, but with a prefix we don't know. Passing
				// it through would leak it, so abort instead.
				return m.abort(tctx, req, "github:issue", fmt.Sprintf("%s has unexpected shape (unknown prefix)", field))
			}
			mask, err := m.store.Tokenize(val, m.githubKindForField(field), source, "")
			if err != nil {
				return m.abort(tctx, req, "github:issue", err.Error())
			}
			obj[field] = mask
			changed = true
		}
		if changed {
			if out, err = encodeJSON(obj); err != nil {
				return m.abort(tctx, req, "github:issue", err.Error())
			}
		}
	} else {
		// form-encoded: access_token=gho_...&token_type=bearer&scope=...
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return m.abort(tctx, req, "github:issue", "issuance response is not form-encoded")
		}
		for _, field := range githubTokenFields {
			val := form.Get(field)
			if val == "" {
				continue
			}
			if !hasAnyPrefix(val, githubTokenPrefixes) {
				return m.abort(tctx, req, "github:issue", fmt.Sprintf("%s has unexpected shape (unknown prefix)", field))
			}
			mask, err := m.store.Tokenize(val, m.githubKindForField(field), source, "")
			if err != nil {
				return m.abort(tctx, req, "github:issue", err.Error())
			}
			form.Set(field, mask)
			changed = true
		}
		if changed {
			out = []byte(form.Encode())
		}
	}

	if changed {
		setResponseBody(resp, out)
		m.logger.Info("credential_mask: masked github token in issuance response")
		tctx.Annotate("masked", "github:issue")
	}
	return cont
}

func (m *CredMask) maskOAuthRefresh(tctx *transform.TransformContext, req *http.Request, resp *http.Response, p *oauthProvider) *transform.TransformResult {
	cont := &transform.TransformResult{Action: transform.ActionContinue}

	body, err := readDecodedBody(resp, tokenMaxDecodedBytes)
	if err != nil {
		return m.abort(tctx, req, p.kind, fmt.Sprintf("cannot read token response: %v", err))
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return cont
	}
	ctype := resp.Header.Get("Content-Type")
	looksLikeJSON := strings.Contains(ctype, "application/json") || bytes.HasPrefix(bytes.TrimSpace(body), []byte("{"))
	obj, ok := parseJSONObject(body)
	if !ok {
		if looksLikeJSON {
			// A JSON body that does not parse may be a token response cut
			// short by proxy.max_response_body_bytes, with the real refresh
			// token still in the part that arrived. Passing it through would
			// leak it, so abort instead.
			return m.abort(tctx, req, p.kind, "token response is JSON but does not parse (truncated?)")
		}
		return cont // not a JSON token response (error page, other endpoint)
	}
	val, ok := obj[p.field].(string)
	if !ok || val == "" {
		return cont
	}
	if !strings.HasPrefix(val, p.maskPrefix) {
		// There IS a refresh token, but not in the shape we expect. Passing
		// it through would leak it, so abort instead.
		return m.abort(tctx, req, p.kind, "refresh token has unexpected shape (prefix mismatch)")
	}
	if m.store.IsMask(val) {
		return cont // already a mask; never mask a mask
	}
	mask, err := m.store.Tokenize(val, p.kind, sourceOf(req), p.maskPrefix)
	if err != nil {
		return m.abort(tctx, req, p.kind, err.Error())
	}
	obj[p.field] = mask
	out, err := encodeJSON(obj)
	if err != nil {
		return m.abort(tctx, req, p.kind, err.Error())
	}
	setResponseBody(resp, out)
	m.logger.Info("credential_mask: masked refresh token in response", slog.String("kind", p.kind))
	tctx.Annotate("masked", p.kind)
	return cont
}

// abort replaces the upstream response with a 500 so a login/refresh fails
// loudly rather than letting a real credential reach the client.
func (m *CredMask) abort(tctx *transform.TransformContext, req *http.Request, kind, reason string) *transform.TransformResult {
	m.logger.Error("credential_mask: failed to mask credential, aborting flow",
		slog.String("kind", kind), slog.String("reason", reason))
	tctx.Annotate("aborted", kind)
	tctx.Annotate("abort_reason", reason)

	msg := []byte("credential_mask: failed to mask credential; flow aborted\n")
	return &transform.TransformResult{
		Action: transform.ActionReject,
		Response: &http.Response{
			StatusCode:    http.StatusInternalServerError,
			Status:        "500 Internal Server Error",
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
			Body:          transform.NewBufferedBodyFromBytes(msg),
			ContentLength: int64(len(msg)),
			Request:       req,
		},
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// readDecodedBody reads the response body and undoes gzip if present. The
// pipeline rewinds the buffered body for the next transform, so reading it
// here is safe. Any encoding other than gzip/identity is an error.
//
// A decoded body longer than limit returns errDecodedTooLarge. For gzip the
// limit is applied while decompressing, so a small body that expands to a
// huge one (a decompression bomb) stops at limit+1 bytes instead of filling
// memory.
//
// A body whose Content-Length is already over limit also returns
// errDecodedTooLarge, before any of it is read. The headers arrive first, so
// this costs nothing. A body of unknown length (chunked, HTTP/2 without
// Content-Length) is still read in full before the limit applies: the
// pipeline's BufferedBody reads the whole body on the first Read. On the
// login/refresh paths that body comes from the provider over TLS;
// proxy.max_response_body_bytes caps it if needed.
func readDecodedBody(resp *http.Response, limit int64) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}
	if resp.ContentLength > limit {
		return nil, errDecodedTooLarge
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	switch enc {
	case "", "identity":
		if int64(len(raw)) > limit {
			return nil, errDecodedTooLarge
		}
		return raw, nil
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer zr.Close()
		// Read one byte past the limit so "exactly at the limit" (fine) can
		// be told apart from "over the limit".
		decoded, err := io.ReadAll(io.LimitReader(zr, limit+1))
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		if int64(len(decoded)) > limit {
			return nil, errDecodedTooLarge
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("unsupported Content-Encoding %q", enc)
	}
}

// setResponseBody replaces the body with plain (uncompressed) bytes and
// makes every length/encoding header agree with them. The proxy also sets
// Content-Length from a buffered body when it writes the response; setting
// it here keeps the response correct for any later transform too.
func setResponseBody(resp *http.Response, data []byte) {
	resp.Body = transform.NewBufferedBodyFromBytes(data)
	resp.ContentLength = int64(len(data))
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Transfer-Encoding")
	resp.Header.Set("Content-Length", strconv.Itoa(len(data)))
	resp.TransferEncoding = nil
	resp.Uncompressed = false
}

// parseJSONObject decodes a JSON object, keeping numbers exact.
func parseJSONObject(data []byte) (map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return nil, false
	}
	return obj, true
}

// encodeJSON encodes without HTML escaping and without a trailing newline.
func encodeJSON(obj map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// bodyIsUnencoded reports whether a request body is plain bytes: no
// Content-Encoding, or the no-op "identity". A compressed request body is
// left alone (the mask goes upstream and the refresh fails safely).
func bodyIsUnencoded(h http.Header) bool {
	enc := strings.ToLower(strings.TrimSpace(h.Get("Content-Encoding")))
	return enc == "" || enc == "identity"
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
