package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/config"
	"github.com/ironsh/iron-proxy/internal/management"
	"github.com/ironsh/iron-proxy/internal/mcp"
	"github.com/ironsh/iron-proxy/internal/mcpgateway"
	"github.com/ironsh/iron-proxy/internal/postgres"
	"github.com/ironsh/iron-proxy/internal/transform"
)

// allowed runs a request for host through the pipeline currently held and
// reports whether the allowlist let it through.
func allowed(t *testing.T, holder *transform.PipelineHolder, host string) bool {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
	req.Host = host
	req.Body = transform.NewBufferedBody(http.NoBody, 0)
	var traces []transform.TransformTrace
	resp, err := holder.Load().ProcessRequest(context.Background(), &transform.TransformContext{}, req, &traces)
	require.NoError(t, err)
	return resp == nil
}

// TestReload_DomainsFile runs the real reload function the way a temp-allowlist
// UI would use it: the config file never changes, only domains_file does, and
// each change takes effect on reload. A bad file is refused as a validation
// error (422) and the running allowlist is kept.
func TestReload_DomainsFile(t *testing.T) {
	dir := t.TempDir()
	tempFile := filepath.Join(dir, "allowlist-temp.txt")
	require.NoError(t, os.WriteFile(tempFile, []byte("# temporary entries\n"), 0o600))

	configPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(fmt.Sprintf(`
dns:
  enabled: false
tls:
  ca_cert: /unused/ca.crt
  ca_key: /unused/ca.key
transforms:
  - name: allowlist
    config:
      domains: ["api.github.com"]
      domains_file: %q
`, tempFile)), 0o600))

	startCfg, err := config.LoadConfig(configPath)
	require.NoError(t, err)
	startPipeline, err := buildPipeline(startCfg.Transforms, transform.BodyLimits{}, discardLogger())
	require.NoError(t, err)
	holder := transform.NewPipelineHolder(startPipeline)
	reload := newReloadFunc(configPath, startCfg.TLS, holder,
		mcp.NewPolicyHolder(nil), mcpgateway.NewHolder(nil),
		postgres.NewManager(discardLogger()), transform.BodyLimits{}, discardLogger())

	require.True(t, allowed(t, holder, "api.github.com"), "inline domain allowed at start")
	require.False(t, allowed(t, holder, "example.org"), "not allowed before it is added")

	// Add a temporary entry: allowed only after the reload.
	require.NoError(t, os.WriteFile(tempFile, []byte("example.org\n"), 0o600))
	require.False(t, allowed(t, holder, "example.org"), "file change alone does nothing until reload")
	require.NoError(t, reload(context.Background()))
	require.True(t, allowed(t, holder, "example.org"), "allowed after reload")
	require.True(t, allowed(t, holder, "api.github.com"), "inline domain still allowed")

	// A bad entry is refused and the running allowlist is kept.
	running := holder.Load()
	require.NoError(t, os.WriteFile(tempFile, []byte("example.org\n*\n"), 0o600))
	err = reload(context.Background())
	var verr *management.ValidationError
	require.True(t, errors.As(err, &verr), "want a ValidationError (422), got %v", err)
	require.ErrorContains(t, err, "domains_file")
	require.Same(t, running, holder.Load(), "running pipeline must be kept")
	require.False(t, allowed(t, holder, "evil.com"), "the bad '*' entry never took effect")
	require.True(t, allowed(t, holder, "example.org"), "previous entries still allowed")

	// A missing file is refused the same way.
	require.NoError(t, os.Remove(tempFile))
	err = reload(context.Background())
	require.True(t, errors.As(err, &verr), "want a ValidationError (422), got %v", err)
	require.Same(t, running, holder.Load(), "running pipeline must be kept")

	// Revoke the entry: blocked again after the reload.
	require.NoError(t, os.WriteFile(tempFile, []byte("# temporary entries\n"), 0o600))
	require.NoError(t, reload(context.Background()))
	require.False(t, allowed(t, holder, "example.org"), "blocked again after revoke and reload")
	require.True(t, allowed(t, holder, "api.github.com"), "inline domain unaffected")
}
