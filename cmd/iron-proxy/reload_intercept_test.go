package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/config"
	"github.com/ironsh/iron-proxy/internal/management"
	"github.com/ironsh/iron-proxy/internal/mcp"
	"github.com/ironsh/iron-proxy/internal/mcpgateway"
	"github.com/ironsh/iron-proxy/internal/postgres"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func TestCheckInterceptUnchanged(t *testing.T) {
	running := config.TLS{
		Intercept:        []string{"github.com", "*.amazonaws.com"},
		InterceptExclude: []string{"ssm.af-south-1.amazonaws.com"},
	}
	tests := []struct {
		name    string
		next    config.TLS
		wantErr string // "" means the reload is allowed
	}{
		{
			name:    "same lists",
			next:    running,
			wantErr: "",
		},
		{
			name: "same lists in another order",
			next: config.TLS{
				Intercept:        []string{"*.amazonaws.com", "github.com"},
				InterceptExclude: []string{"ssm.af-south-1.amazonaws.com"},
			},
			wantErr: "",
		},
		{
			name: "host added to intercept",
			next: config.TLS{
				Intercept:        []string{"github.com", "*.amazonaws.com", "example.com"},
				InterceptExclude: []string{"ssm.af-south-1.amazonaws.com"},
			},
			wantErr: "tls.intercept changed",
		},
		{
			name: "intercept removed entirely",
			next: config.TLS{
				InterceptExclude: []string{"ssm.af-south-1.amazonaws.com"},
			},
			wantErr: "tls.intercept changed",
		},
		{
			name: "host removed from intercept_exclude",
			next: config.TLS{
				Intercept: []string{"github.com", "*.amazonaws.com"},
			},
			wantErr: "tls.intercept_exclude changed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkInterceptUnchanged(running, tt.next)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
			require.ErrorContains(t, err, "restart iron-proxy")
		})
	}
}

// TestReload_InterceptChange runs the real reload function against config
// files: a changed interception list is refused as a validation error (422)
// and the running pipeline is kept; an allowlist-only change still reloads.
func TestReload_InterceptChange(t *testing.T) {
	const startConfig = `
dns:
  enabled: false
tls:
  ca_cert: /unused/ca.crt
  ca_key: /unused/ca.key
  intercept: ["github.com"]
transforms:
  - name: allowlist
    config:
      domains: ["github.com"]
`
	tests := []struct {
		name         string
		newConfig    string
		wantRejected bool
	}{
		{
			name:         "allowlist change reloads",
			newConfig:    strings.Replace(startConfig, `domains: ["github.com"]`, `domains: ["github.com", "example.com"]`, 1),
			wantRejected: false,
		},
		{
			name:         "intercept change is rejected",
			newConfig:    strings.Replace(startConfig, `intercept: ["github.com"]`, `intercept: ["github.com", "example.com"]`, 1),
			wantRejected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(path, []byte(startConfig), 0o600))
			startCfg, err := config.LoadConfig(path)
			require.NoError(t, err)

			original := transform.NewPipeline(nil, transform.BodyLimits{}, discardLogger())
			holder := transform.NewPipelineHolder(original)
			reload := newReloadFunc(path, startCfg.TLS, holder,
				mcp.NewPolicyHolder(nil), mcpgateway.NewHolder(nil),
				postgres.NewManager(discardLogger()), transform.BodyLimits{}, discardLogger())

			require.NoError(t, os.WriteFile(path, []byte(tt.newConfig), 0o600))
			err = reload(context.Background())

			if !tt.wantRejected {
				require.NoError(t, err)
				require.NotSame(t, original, holder.Load(), "pipeline should have been swapped")
				return
			}
			var verr *management.ValidationError
			require.True(t, errors.As(err, &verr), "want a ValidationError (422), got %v", err)
			require.ErrorContains(t, err, "tls.intercept changed")
			require.Same(t, original, holder.Load(), "running pipeline must be kept")
		})
	}
}
