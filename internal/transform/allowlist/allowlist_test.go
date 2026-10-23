package allowlist

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func result(t *testing.T, a *Allowlist, host string) *transform.TransformResult {
	t.Helper()
	req := httptest.NewRequest("GET", "http://"+host+"/", nil)
	req.Host = host
	res, err := a.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	return res
}

func resultWithMethodAndPath(t *testing.T, a *Allowlist, host, method, path string) *transform.TransformResult {
	t.Helper()
	req := httptest.NewRequest(method, "http://"+host+path, nil)
	req.Host = host
	res, err := a.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	return res
}

// --- Existing tests (backwards compat via New) ---

func TestAllowlist_ExactDomainMatch(t *testing.T) {
	a, err := New([]string{"api.openai.com"}, nil)
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "api.openai.com").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "evil.com").Action)
}

func TestAllowlist_WildcardDomain(t *testing.T) {
	a, err := New([]string{"*.anthropic.com"}, nil)
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "api.anthropic.com").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "docs.api.anthropic.com").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "anthropic.com").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "notanthropic.com").Action)
}

func TestAllowlist_HostWithPort(t *testing.T) {
	a, err := New([]string{"api.openai.com"}, nil)
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "api.openai.com:443").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "evil.com:443").Action)
}

func TestAllowlist_CIDRMatchesLiteralIP(t *testing.T) {
	a, err := New(nil, []string{"10.0.0.0/8"})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "10.0.1.5").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "10.0.1.5:8080").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "8.8.8.8").Action)
}

func TestAllowlist_CIDRDoesNotResolveHostnames(t *testing.T) {
	// Hostnames are never resolved to check against CIDRs — only literal IPs match.
	a, err := New(nil, []string{"10.0.0.0/8"})
	require.NoError(t, err)

	require.Equal(t, transform.ActionReject, result(t, a, "internal.service").Action)
}

func TestAllowlist_MultipleCIDRs(t *testing.T) {
	a, err := New(nil, []string{"10.0.0.0/8", "172.16.0.0/12"})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "10.0.0.1").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "172.16.0.1").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "8.8.8.8").Action)
}

func TestAllowlist_DomainAndCIDRTogether(t *testing.T) {
	a, err := New([]string{"allowed.com"}, []string{"10.0.0.0/8"})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "allowed.com").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "10.0.1.5").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "evil.com").Action)
}

func TestAllowlist_EmptyAllowlistDeniesAll(t *testing.T) {
	a, err := New(nil, nil)
	require.NoError(t, err)

	require.Equal(t, transform.ActionReject, result(t, a, "anything.com").Action)
}

func TestAllowlist_MultipleDomains(t *testing.T) {
	a, err := New([]string{"a.com", "b.com", "*.c.com"}, nil)
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "a.com").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "b.com").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "sub.c.com").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "d.com").Action)
}

func TestAllowlist_InvalidCIDR(t *testing.T) {
	_, err := New(nil, []string{"not-a-cidr"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "parsing CIDR")
}

func TestAllowlist_ResponseIsNoop(t *testing.T) {
	a, err := New(nil, nil)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{StatusCode: http.StatusOK}
	res, err := a.TransformResponse(context.Background(), &transform.TransformContext{}, req, resp)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
}

func TestAllowlist_Name(t *testing.T) {
	a, err := New(nil, nil)
	require.NoError(t, err)
	require.Equal(t, "allowlist", a.Name())
}

// --- Method matching tests ---

func TestAllowlist_MethodAllowed(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			Host:    "api.openai.com",
			Methods: []string{"GET", "POST"},
		}},
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "POST", "/").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "DELETE", "/").Action)
}

func TestAllowlist_MethodsCaseInsensitive(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			Host:    "api.openai.com",
			Methods: []string{"post"},
		}},
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "POST", "/").Action)
}

func TestAllowlist_NoMethodsAllowsAll(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			Host: "api.openai.com",
		}},
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "POST", "/").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "DELETE", "/").Action)
}

// --- Path matching tests ---

func TestAllowlist_PathGlob(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			Host:  "api.openai.com",
			Paths: []string{"/v1/*"},
		}},
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/models").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/chat/completions").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v2/models").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/").Action)
}

func TestAllowlist_PathExact(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			Host:  "api.openai.com",
			Paths: []string{"/health"},
		}},
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/health").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/health/deep").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/other").Action)
}

func TestAllowlist_NoPathsAllowsAll(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			Host: "api.openai.com",
		}},
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/anything").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/models").Action)
}

func TestAllowlist_MultiplePaths(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			Host:  "api.openai.com",
			Paths: []string{"/v1/chat", "/v1/models"},
		}},
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/chat").Action)
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/models").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/other").Action)
}

// --- Combined tests ---

func TestAllowlist_HostMethodPathCombined(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			Host:    "api.openai.com",
			Methods: []string{"POST"},
			Paths:   []string{"/v1/*"},
		}},
	})
	require.NoError(t, err)

	// All three match
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.openai.com", "POST", "/v1/chat").Action)
	// Wrong method
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "GET", "/v1/chat").Action)
	// Wrong path
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.openai.com", "POST", "/v2/chat").Action)
	// Wrong host
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "evil.com", "POST", "/v1/chat").Action)
}

func TestAllowlist_MultiRuleSecondMatches(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{
			{Host: "api.openai.com", Methods: []string{"POST"}},
			{Host: "api.anthropic.com", Methods: []string{"GET"}},
		},
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "api.anthropic.com", "GET", "/").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "api.anthropic.com", "POST", "/").Action)
}

func TestAllowlist_FlatDomainsAndRulesMixed(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Domains: []string{"open.com"},
		Rules: []hostmatch.RuleConfig{{
			Host:    "restricted.com",
			Methods: []string{"GET"},
		}},
	})
	require.NoError(t, err)

	// Flat domain: all methods allowed
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "open.com", "DELETE", "/anything").Action)
	// Rule: only GET
	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "restricted.com", "GET", "/").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "restricted.com", "POST", "/").Action)
}

func TestAllowlist_RuleWithCIDR(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			CIDR:    "10.0.0.0/8",
			Methods: []string{"GET"},
		}},
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, resultWithMethodAndPath(t, a, "10.0.1.5", "GET", "/").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "10.0.1.5", "POST", "/").Action)
	require.Equal(t, transform.ActionReject, resultWithMethodAndPath(t, a, "internal.service", "GET", "/").Action)
}

// --- Warn mode tests ---

func TestAllowlist_WarnModeAllowsBlockedRequests(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Domains: []string{"api.openai.com"},
		Warn:    true,
	})
	require.NoError(t, err)

	// Allowed request: no annotation
	tctx := &transform.TransformContext{}
	req := httptest.NewRequest("GET", "http://api.openai.com/", nil)
	req.Host = "api.openai.com"
	res, err := a.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	require.Nil(t, tctx.DrainAnnotations())

	// Blocked request in warn mode: continues with annotation
	tctx2 := &transform.TransformContext{}
	req2 := httptest.NewRequest("GET", "http://evil.com/", nil)
	req2.Host = "evil.com"
	res2, err := a.TransformRequest(context.Background(), tctx2, req2)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res2.Action)
	annotations := tctx2.DrainAnnotations()
	require.Equal(t, "warn", annotations["action"])
}

func TestAllowlist_WarnFalseStillRejects(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Domains: []string{"api.openai.com"},
		Warn:    false,
	})
	require.NoError(t, err)

	require.Equal(t, transform.ActionReject, result(t, a, "evil.com").Action)
}

func TestAllowlist_WarnModeWithRules(t *testing.T) {
	a, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{
			Host:    "api.openai.com",
			Methods: []string{"GET"},
		}},
		Warn: true,
	})
	require.NoError(t, err)

	// Wrong method in warn mode: continues with annotation
	tctx := &transform.TransformContext{}
	req := httptest.NewRequest("POST", "http://api.openai.com/", nil)
	req.Host = "api.openai.com"
	res, err := a.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res.Action)
	annotations := tctx.DrainAnnotations()
	require.Equal(t, "warn", annotations["action"])

	// Wrong host in warn mode: continues with annotation
	tctx2 := &transform.TransformContext{}
	req2 := httptest.NewRequest("GET", "http://evil.com/", nil)
	req2.Host = "evil.com"
	res2, err := a.TransformRequest(context.Background(), tctx2, req2)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, res2.Action)
	annotations2 := tctx2.DrainAnnotations()
	require.Equal(t, "warn", annotations2["action"])
}

// --- Validation tests ---

func TestAllowlist_RuleBothHostAndCIDR(t *testing.T) {
	_, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{Host: "a.com", CIDR: "10.0.0.0/8"}},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "mutually exclusive")
}

func TestAllowlist_RuleNeitherHostNorCIDR(t *testing.T) {
	_, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{Methods: []string{"GET"}}},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "one of host or cidr is required")
}

func TestAllowlist_RuleInvalidPath(t *testing.T) {
	_, err := newFromConfig(allowlistConfig{
		Rules: []hostmatch.RuleConfig{{Host: "a.com", Paths: []string{"no-leading-slash"}}},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "must start with /")
}

// --- matchPath unit tests ---

func TestMatchPath(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"/v1/*", "/v1/models", true},
		{"/v1/*", "/v1/chat/completions", true},
		{"/v1/*", "/v1", true},
		{"/v1/*", "/v2/models", false},
		{"/v1/*", "/", false},
		{"/health", "/health", true},
		{"/health", "/health/deep", false},
		{"/health", "/other", false},
		{"/*", "/anything", true},
		{"/*", "/", true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.pattern, tt.path), func(t *testing.T) {
			require.Equal(t, tt.want, hostmatch.MatchPath(tt.pattern, tt.path))
		})
	}
}

// --- domains_file ---

func writeDomainsFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "allowlist-temp.txt")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestAllowlist_DomainsFileAddsToInline(t *testing.T) {
	path := writeDomainsFile(t, "# temporary entries\n\nexample.org\n  *.temp.example.net  \n")
	a, err := newFromConfig(allowlistConfig{Domains: []string{"api.github.com"}, DomainsFile: path})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "api.github.com").Action, "inline domain still allowed")
	require.Equal(t, transform.ActionContinue, result(t, a, "example.org").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "a.temp.example.net").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "temp.example.net").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "evil.com").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "sub.example.org").Action, "exact entry is not a wildcard")
}

func TestAllowlist_DomainsFileEmptyAddsNothing(t *testing.T) {
	path := writeDomainsFile(t, "# nothing yet\n")
	a, err := newFromConfig(allowlistConfig{Domains: []string{"api.github.com"}, DomainsFile: path})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, a, "api.github.com").Action)
	require.Equal(t, transform.ActionReject, result(t, a, "example.org").Action)
}

func TestAllowlist_DomainsFileReadAtBuild(t *testing.T) {
	// The file is read each time the transform is built, which is what a
	// reload does; an already-built transform does not change.
	path := writeDomainsFile(t, "example.org\n")
	before, err := newFromConfig(allowlistConfig{DomainsFile: path})
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(path, []byte("example.net\n"), 0o600))
	after, err := newFromConfig(allowlistConfig{DomainsFile: path})
	require.NoError(t, err)

	require.Equal(t, transform.ActionContinue, result(t, before, "example.org").Action)
	require.Equal(t, transform.ActionReject, result(t, before, "example.net").Action)
	require.Equal(t, transform.ActionReject, result(t, after, "example.org").Action, "removed entry no longer allowed")
	require.Equal(t, transform.ActionContinue, result(t, after, "example.net").Action)
}

func TestAllowlist_DomainsFileRejects(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{name: "bare wildcard opens everything", content: "*\n", wantErr: "not a fully qualified hostname"},
		{name: "wildcard over a single label", content: "*.com\n", wantErr: "at least two labels"},
		{name: "single-label name", content: "localhost\n", wantErr: "not a fully qualified hostname"},
		{name: "glob character", content: "exa?ple.com\n", wantErr: "only letters, digits"},
		{name: "mid-name wildcard", content: "api.*.example.com\n", wantErr: "only letters, digits"},
		{name: "scheme or path", content: "https://example.com/\n", wantErr: "only letters, digits"},
		{name: "two entries on one line", content: "example.com example.org\n", wantErr: "one domain per line"},
		{name: "empty label", content: "example..com\n", wantErr: "empty or over-long label"},
		{name: "leading hyphen", content: "-example.com\n", wantErr: "cannot start or end with '-'"},
		{name: "bad line reported with its number", content: "example.org\n\n*\n", wantErr: "line 3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeDomainsFile(t, tt.content)
			_, err := newFromConfig(allowlistConfig{Domains: []string{"api.github.com"}, DomainsFile: path})
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestAllowlist_DomainsFileErrors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		_, err := newFromConfig(allowlistConfig{DomainsFile: filepath.Join(t.TempDir(), "absent.txt")})
		require.ErrorContains(t, err, "domains_file")
		require.ErrorIs(t, err, os.ErrNotExist)
	})
	t.Run("relative path", func(t *testing.T) {
		_, err := newFromConfig(allowlistConfig{DomainsFile: "allowlist-temp.txt"})
		require.ErrorContains(t, err, "must be an absolute path")
	})
	t.Run("directory", func(t *testing.T) {
		_, err := newFromConfig(allowlistConfig{DomainsFile: t.TempDir()})
		require.ErrorContains(t, err, "not a regular file")
	})
	t.Run("over the size limit", func(t *testing.T) {
		path := writeDomainsFile(t, strings.Repeat("a", maxDomainsFileBytes+1))
		_, err := newFromConfig(allowlistConfig{DomainsFile: path})
		require.ErrorContains(t, err, "byte limit")
	})
}

func TestAllowlist_DomainsFileFromYAML(t *testing.T) {
	path := writeDomainsFile(t, "example.org\n")
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(fmt.Sprintf("domains: [api.github.com]\ndomains_file: %q\n", path)), &node))
	tr, err := factory(*node.Content[0], nil)
	require.NoError(t, err)
	a := tr.(*Allowlist)
	require.Equal(t, transform.ActionContinue, result(t, a, "example.org").Action)
	require.Equal(t, transform.ActionContinue, result(t, a, "api.github.com").Action)
}
