package credmask

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// newStoreDir makes a store dir with a fresh master key.
func newStoreDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "master.key"), []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o600))
	return dir
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(newStoreDir(t))
	require.NoError(t, err)
	return s
}

const realGitHub = "gho_16C7e42F292c6912E7710c838347Ae178B4a"

func TestTokenizeSameShapeAndIdempotent(t *testing.T) {
	s := newTestStore(t)

	mask, err := s.Tokenize(realGitHub, "github:access_token", "10.0.0.5", "")
	require.NoError(t, err)
	require.NotEqual(t, realGitHub, mask)
	require.True(t, strings.HasPrefix(mask, "gho_"))
	require.Len(t, mask, len(realGitHub))

	again, err := s.Tokenize(realGitHub, "github:access_token", "10.0.0.5", "")
	require.NoError(t, err)
	require.Equal(t, mask, again, "same secret from same source must return the same mask")

	other, err := s.Tokenize(realGitHub, "github:access_token", "10.0.0.6", "")
	require.NoError(t, err)
	require.NotEqual(t, mask, other, "a different source must get its own mask")
}

func TestResolveEnforcesSource(t *testing.T) {
	s := newTestStore(t)
	mask, err := s.Tokenize(realGitHub, "github:access_token", "10.0.0.5", "")
	require.NoError(t, err)

	real, ok, err := s.Resolve(mask, "github:access_token", "10.0.0.5", true)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, realGitHub, real)

	_, ok, err = s.Resolve(mask, "github:access_token", "10.0.0.9", true)
	require.NoError(t, err)
	require.False(t, ok, "mask presented from another source must not resolve")

	real, ok, err = s.Resolve(mask, "github:access_token", "10.0.0.9", false)
	require.NoError(t, err)
	require.True(t, ok, "with enforcement off any source resolves")
	require.Equal(t, realGitHub, real)

	_, ok, err = s.Resolve("gho_notOneOfOurs", "github:access_token", "10.0.0.5", true)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestStorePersistsAcrossReopen(t *testing.T) {
	dir := newStoreDir(t)
	s1, err := Open(dir)
	require.NoError(t, err)
	mask, err := s1.Tokenize(realGitHub, "github:access_token", "10.0.0.5", "")
	require.NoError(t, err)

	info, err := os.Stat(filepath.Join(dir, "vault.json"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	raw, err := os.ReadFile(filepath.Join(dir, "vault.json"))
	require.NoError(t, err)
	require.NotContains(t, string(raw), realGitHub, "the real secret must never be stored in clear")

	s2, err := Open(dir)
	require.NoError(t, err)
	real, ok, err := s2.Resolve(mask, "github:access_token", "10.0.0.5", true)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, realGitHub, real)
}

func TestCiphertextIsBoundToItsMask(t *testing.T) {
	dir := newStoreDir(t)
	s1, err := Open(dir)
	require.NoError(t, err)
	maskA, err := s1.Tokenize("gho_aaaaaaaaaaaaaaaaaaaa", "k", "10.0.0.5", "")
	require.NoError(t, err)
	maskB, err := s1.Tokenize("gho_bbbbbbbbbbbbbbbbbbbb", "k", "10.0.0.5", "")
	require.NoError(t, err)

	// Swap the two ciphertexts on disk.
	path := filepath.Join(dir, "vault.json")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var records []storeRecord
	require.NoError(t, json.Unmarshal(raw, &records))
	records[0].SecretEnc, records[1].SecretEnc = records[1].SecretEnc, records[0].SecretEnc
	raw, err = json.Marshal(records)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))

	s2, err := Open(dir)
	require.NoError(t, err)
	for _, m := range []string{maskA, maskB} {
		_, _, err := s2.Resolve(m, "k", "10.0.0.5", true)
		require.ErrorIs(t, err, ErrStore, "a ciphertext moved to another mask must not decrypt")
	}
}

func TestOpenFailsWithoutMasterKey(t *testing.T) {
	_, err := Open(t.TempDir())
	require.ErrorIs(t, err, ErrStore)
	require.Contains(t, err.Error(), "master key")
}

func TestOpenRejectsShortMasterKey(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "master.key"), []byte(base64.StdEncoding.EncodeToString([]byte("short"))), 0o600))
	_, err := Open(dir)
	require.ErrorIs(t, err, ErrStore)
}

func TestTokenizeRefusals(t *testing.T) {
	s := newTestStore(t)

	_, err := s.Tokenize("", "k", "10.0.0.5", "")
	require.ErrorIs(t, err, ErrStore)

	_, err = s.Tokenize(realGitHub, "k", "", "")
	require.ErrorIs(t, err, ErrStore, "no source identity must refuse")

	_, err = s.Tokenize("rt.1.abc", "codex:refresh", "10.0.0.5", "sk-ant-ort01-")
	require.ErrorIs(t, err, ErrStore, "prefix mismatch must refuse")

	_, err = s.Tokenize("gho_", "k", "10.0.0.5", "")
	require.ErrorIs(t, err, ErrStore, "token with no body must refuse")
}

func TestMaskPrefixKept(t *testing.T) {
	s := newTestStore(t)
	real := "sk-ant-ort01-AbCdEf0123456789-xyz"
	mask, err := s.Tokenize(real, "claude:refresh", "10.0.0.5", "sk-ant-ort01-")
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(mask, "sk-ant-ort01-"))
	require.Len(t, mask, len(real))
	require.True(t, s.IsMask(mask))
	require.False(t, s.IsMask(real))

	got, ok := s.MaskFor(real, "10.0.0.5")
	require.True(t, ok)
	require.Equal(t, mask, got)
}

func TestOpenSharedReturnsSameStore(t *testing.T) {
	dir := newStoreDir(t)
	a, err := OpenShared(dir)
	require.NoError(t, err)
	b, err := OpenShared(dir + "/")
	require.NoError(t, err)
	require.Same(t, a, b, "a config reload must reuse the live store, not open a second copy")
}
