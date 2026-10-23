// Package allowlist implements a default-deny domain and CIDR allowlist transform.
//
// Domains can be listed inline (domains) and, optionally, in a separate file
// (domains_file). The file's domains are added to the inline ones; they never
// narrow them. The file is read when the transform is built: at startup and on
// every /v1/reload. That lets a separate process own the file (for example a
// UI for temporary entries) while the config file stays owned by whatever
// deploys it, and a change takes effect with a reload:
//
//	transforms:
//	  - name: allowlist
//	    config:
//	      domains: ["api.github.com", "*.npmjs.org"]
//	      domains_file: /var/lib/iron-proxy/allowlist-temp.txt
//
// The file holds one domain per line: an exact hostname or a "*." wildcard
// over a name of at least two labels. Stricter than inline domains: a bare
// "*", "*.com" or any other glob character is refused (see
// validateFileDomain). Blank lines and lines starting with "#" are ignored,
// as is surrounding whitespace. A missing or unreadable file, an invalid
// entry, or a file over maxDomainsFileBytes is an error: at startup the proxy
// does not start, and on reload the reload is refused with 422 and the
// running pipeline is kept.
package allowlist

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("allowlist", factory)
}

// Allowlist is a default-deny transform that checks request hosts, methods,
// and paths against a set of rules.
type Allowlist struct {
	rules []hostmatch.Rule
	warn  bool
}

type allowlistConfig struct {
	Domains     []string               `yaml:"domains"`
	DomainsFile string                 `yaml:"domains_file"`
	CIDRs       []string               `yaml:"cidrs"`
	Rules       []hostmatch.RuleConfig `yaml:"rules"`
	Warn        bool                   `yaml:"warn"`
}

// maxDomainsFileBytes caps the size of domains_file. It is meant for a short
// list of extra entries, and the cap stops a runaway writer from making every
// reload read an unbounded file.
const maxDomainsFileBytes = 1 << 20

// validateFileDomain checks one domains_file entry. The file is meant to be
// written by something other than the config's author (a UI for temporary
// entries), so it is held to a stricter form than inline domains: an exact
// hostname, or "*." followed by a hostname. A bare "*" (every host), a
// wildcard over a single label such as "*.com", and any other glob character
// are refused, so one bad line cannot open the allowlist wide.
func validateFileDomain(d string) error {
	name := strings.TrimPrefix(d, "*.")
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		if strings.HasPrefix(d, "*.") {
			return fmt.Errorf("%q: a wildcard needs at least two labels after \"*.\" (\"*.example.com\", not \"*.com\")", d)
		}
		return fmt.Errorf("%q: not a fully qualified hostname", d)
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("%q: empty or over-long label", d)
		}
		for _, r := range label {
			isAlnum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
			if !isAlnum && r != '-' {
				return fmt.Errorf("%q: only letters, digits, '-' and a leading \"*.\" are allowed", d)
			}
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("%q: a label cannot start or end with '-'", d)
		}
	}
	return nil
}

// readDomainsFile returns the domains listed in path, one per line, skipping
// blank lines and "#" comments. Every entry must pass validateFileDomain.
func readDomainsFile(path string) ([]string, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("allowlist domains_file %q: must be an absolute path", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("allowlist domains_file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("allowlist domains_file %q: not a regular file", path)
	}
	if info.Size() > maxDomainsFileBytes {
		return nil, fmt.Errorf("allowlist domains_file %q: %d bytes, over the %d-byte limit", path, info.Size(), maxDomainsFileBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("allowlist domains_file: %w", err)
	}
	if len(data) > maxDomainsFileBytes {
		// The file grew between Stat and ReadFile.
		return nil, fmt.Errorf("allowlist domains_file %q: over the %d-byte limit", path, maxDomainsFileBytes)
	}

	var domains []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 4096), maxDomainsFileBytes)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsAny(line, " \t") {
			return nil, fmt.Errorf("allowlist domains_file %q line %d: one domain per line, got %q", path, lineNo, line)
		}
		if err := validateFileDomain(line); err != nil {
			return nil, fmt.Errorf("allowlist domains_file %q line %d: %w", path, lineNo, err)
		}
		domains = append(domains, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("allowlist domains_file %q: %w", path, err)
	}
	return domains, nil
}

func factory(cfg yaml.Node, _ *slog.Logger) (transform.Transformer, error) {
	var c allowlistConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing allowlist config: %w", err)
	}
	return newFromConfig(c)
}

func newFromConfig(cfg allowlistConfig) (*Allowlist, error) {
	var rules []hostmatch.Rule

	// Flat domains → rules with no method/path restrictions.
	for _, d := range cfg.Domains {
		m, err := hostmatch.New([]string{d}, nil)
		if err != nil {
			return nil, err
		}
		rules = append(rules, hostmatch.Rule{Matcher: m})
	}

	// Domains from domains_file, the same way. Read on every build, so a
	// reload picks up changes to the file.
	if cfg.DomainsFile != "" {
		fileDomains, err := readDomainsFile(cfg.DomainsFile)
		if err != nil {
			return nil, err
		}
		for _, d := range fileDomains {
			m, err := hostmatch.New([]string{d}, nil)
			if err != nil {
				return nil, fmt.Errorf("allowlist domains_file %q: %w", cfg.DomainsFile, err)
			}
			rules = append(rules, hostmatch.Rule{Matcher: m})
		}
	}

	// Flat CIDRs → rules with no method/path restrictions.
	for _, c := range cfg.CIDRs {
		m, err := hostmatch.New(nil, []string{c})
		if err != nil {
			return nil, err
		}
		rules = append(rules, hostmatch.Rule{Matcher: m})
	}

	// Explicit rules with optional method/path restrictions.
	compiled, err := hostmatch.CompileRulesAllowRequireTLS(cfg.Rules, "allowlist")
	if err != nil {
		return nil, err
	}
	rules = append(rules, compiled...)

	return &Allowlist{rules: rules, warn: cfg.Warn}, nil
}

// New creates an Allowlist from domain globs and CIDR strings.
// All methods and paths are allowed. This is the backwards-compatible constructor.
func New(domains []string, cidrs []string) (*Allowlist, error) {
	return newFromConfig(allowlistConfig{Domains: domains, CIDRs: cidrs})
}

func (a *Allowlist) Name() string { return "allowlist" }

func (a *Allowlist) TransformRequest(_ context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if hostmatch.MatchAnyRule(a.rules, req) {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	if a.warn {
		tctx.Annotate("action", "warn")
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	return &transform.TransformResult{Action: transform.ActionReject}, nil
}

func (a *Allowlist) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}
