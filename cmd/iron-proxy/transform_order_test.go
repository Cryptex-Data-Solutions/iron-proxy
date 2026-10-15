package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/config"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func transformsNamed(names ...string) []config.Transform {
	out := make([]config.Transform, len(names))
	for i, n := range names {
		out[i] = config.Transform{Name: n}
	}
	return out
}

func TestValidateTransformOrder(t *testing.T) {
	tests := []struct {
		name    string
		order   []string
		wantErr string
	}{
		{name: "body_capture before credential_mask", order: []string{"allowlist", "body_capture", "credential_mask"}},
		{name: "credential_mask without body_capture", order: []string{"allowlist", "credential_mask"}},
		{name: "body_capture without credential_mask", order: []string{"allowlist", "body_capture"}},
		{name: "neither", order: []string{"allowlist", "secrets"}},
		{name: "empty", order: nil},
		{
			name:    "body_capture right after credential_mask",
			order:   []string{"allowlist", "credential_mask", "body_capture"},
			wantErr: "transforms[2]: body_capture must come before credential_mask (transforms[1])",
		},
		{
			name:    "body_capture later after credential_mask",
			order:   []string{"credential_mask", "allowlist", "secrets", "body_capture"},
			wantErr: "transforms[3]: body_capture must come before credential_mask (transforms[0])",
		},
		{
			name:    "a second body_capture after credential_mask",
			order:   []string{"body_capture", "credential_mask", "body_capture"},
			wantErr: "transforms[2]: body_capture must come before credential_mask (transforms[1])",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTransformOrder(transformsNamed(tc.order...))
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// buildPipeline is the path for startup and every reload, so the check must
// run there before any transform is constructed.
func TestBuildPipelineRejectsBodyCaptureAfterCredentialMask(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := buildPipeline(transformsNamed("credential_mask", "body_capture"), transform.BodyLimits{}, logger)
	require.Error(t, err)
	require.Contains(t, err.Error(), "body_capture must come before credential_mask")
}
