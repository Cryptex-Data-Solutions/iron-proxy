package credmask

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Store keeps `real secret -> same-shape mask` mappings so the proxy can
// hand the client a mask while the real value stays here.
//
// Layout on disk, inside the configured store_dir:
//
//	master.key  base64 of 32 random bytes. Provisioned by the operator
//	            (e.g. `openssl rand -base64 32`), never generated here,
//	            so a missing key is a loud startup failure, not a silent
//	            new vault.
//	vault.json  every record, rewritten atomically (temp file + rename)
//	            each time a new mask is minted. Mode 0600.
//
// Secret values are AES-256-GCM encrypted with the master key, and the
// mask is the GCM additional data, so a ciphertext cannot be moved onto
// another mask's record. A stolen vault.json alone does not give up the
// secrets.
//
// Lookups by secret (to keep issuance idempotent) use an HMAC keyed from
// the master key, so the file never holds a bare hash someone could grind
// against a guess.
type Store struct {
	mu sync.Mutex

	vaultPath string
	aead      cipher.AEAD
	macKey    []byte

	byMask   map[string]storeRecord
	byLookup map[string]string // lookup HMAC -> mask
}

type storeRecord struct {
	Mask      string    `json:"mask"`
	SecretEnc string    `json:"secret_enc"` // base64(nonce || ciphertext)
	Lookup    string    `json:"lookup_hmac"`
	Source    string    `json:"source"`
	Kind      string    `json:"kind"`
	CreatedAt time.Time `json:"created_at"`
}

// ErrStore is wrapped by every store failure. Callers MUST fail closed on
// it: never forward a real secret to the client because masking failed.
var ErrStore = errors.New("credmask store")

// Stores are shared per directory for the life of the process. A config
// reload (POST /v1/reload) builds a brand new pipeline, which calls the
// factory again; without sharing, the old and new pipelines would each
// hold their own in-memory copy and one could overwrite masks the other
// minted while both were live.
var (
	sharedStoresMu sync.Mutex
	sharedStores   = map[string]*Store{}
)

// OpenShared returns the process-wide Store for dir, opening it on first use.
func OpenShared(dir string) (*Store, error) {
	clean := filepath.Clean(dir)
	sharedStoresMu.Lock()
	defer sharedStoresMu.Unlock()
	if s, ok := sharedStores[clean]; ok {
		return s, nil
	}
	s, err := Open(clean)
	if err != nil {
		return nil, err
	}
	sharedStores[clean] = s
	return s, nil
}

// Open reads the master key and any existing vault.json from dir.
func Open(dir string) (*Store, error) {
	keyPath := filepath.Join(dir, "master.key")
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read master key at %s: %v", ErrStore, keyPath, err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("%w: master key at %s is not base64: %v", ErrStore, keyPath, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: master key at %s must decode to 32 bytes, got %d", ErrStore, keyPath, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStore, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStore, err)
	}

	// Separate key for the lookup HMAC (domain separation from the
	// encryption key), derived from the master key so it needs no state.
	mac := sha256.Sum256(append([]byte("cryptex-credmask-lookup\x00"), key...))

	s := &Store{
		vaultPath: filepath.Join(dir, "vault.json"),
		aead:      aead,
		macKey:    mac[:],
		byMask:    map[string]storeRecord{},
		byLookup:  map[string]string{},
	}

	data, err := os.ReadFile(s.vaultPath)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil // fresh vault
	}
	if err != nil {
		return nil, fmt.Errorf("%w: reading %s: %v", ErrStore, s.vaultPath, err)
	}
	var records []storeRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("%w: parsing %s: %v", ErrStore, s.vaultPath, err)
	}
	for _, r := range records {
		s.byMask[r.Mask] = r
		s.byLookup[r.Lookup] = r.Mask
	}
	return s, nil
}

// lookupHMAC is keyed per (source, kind, secret): the same real token seen
// from two different clients gets two masks, each bound to its own client.
// The kind is part of the key so a mask is only ever reused for the kind it
// was minted as; otherwise Resolve's kind check would reject the reused mask.
func (s *Store) lookupHMAC(secret, kind, source string) string {
	h := hmac.New(sha256.New, s.macKey)
	h.Write([]byte(source))
	h.Write([]byte{0})
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write([]byte(secret))
	return hex.EncodeToString(h.Sum(nil))
}

// Tokenize returns the mask for secret, minting and saving one if new.
// maskPrefix, when non-empty, is the literal prefix the mask keeps (e.g.
// "sk-ant-ort01-"); when empty the prefix is everything up to the last
// underscore (GitHub's "gho_" style).
func (s *Store) Tokenize(secret, kind, source, maskPrefix string) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("%w: refusing to tokenize an empty secret", ErrStore)
	}
	if source == "" {
		return "", fmt.Errorf("%w: refusing to tokenize without a source identity", ErrStore)
	}

	lookup := s.lookupHMAC(secret, kind, source)

	s.mu.Lock()
	defer s.mu.Unlock()

	if mask, ok := s.byLookup[lookup]; ok {
		return mask, nil
	}

	mask, err := sameShapeMask(secret, maskPrefix)
	if err != nil {
		return "", err
	}
	for {
		if _, taken := s.byMask[mask]; !taken {
			break
		}
		if mask, err = sameShapeMask(secret, maskPrefix); err != nil {
			return "", err
		}
	}

	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("%w: nonce: %v", ErrStore, err)
	}
	sealed := s.aead.Seal(nonce, nonce, []byte(secret), []byte(mask))

	rec := storeRecord{
		Mask:      mask,
		SecretEnc: base64.StdEncoding.EncodeToString(sealed),
		Lookup:    lookup,
		Source:    source,
		Kind:      kind,
		CreatedAt: time.Now().UTC(),
	}
	s.byMask[mask] = rec
	s.byLookup[lookup] = mask

	if err := s.saveLocked(); err != nil {
		// Roll back so memory never holds a mask the disk doesn't.
		delete(s.byMask, mask)
		delete(s.byLookup, lookup)
		return "", err
	}
	return mask, nil
}

// Resolve returns the real secret for mask. ok=false means "not ours, minted
// as a different kind, or minted for a different source while enforceSource
// is on": the caller leaves the value alone and the upstream rejects it. An
// error means decryption failed, which the caller must also treat as a
// failure.
//
// kind is the credential kind the caller is about to send (for example
// "github:access_token"). It must match the kind the mask was minted as, so
// a mask for one provider's credential can never be swapped into a request
// to another provider.
func (s *Store) Resolve(mask, kind, source string, enforceSource bool) (string, bool, error) {
	if mask == "" {
		return "", false, nil
	}
	s.mu.Lock()
	rec, found := s.byMask[mask]
	s.mu.Unlock()
	if !found {
		return "", false, nil
	}
	if rec.Kind != kind {
		return "", false, nil
	}
	if enforceSource && rec.Source != source {
		return "", false, nil
	}
	sealed, err := base64.StdEncoding.DecodeString(rec.SecretEnc)
	if err != nil {
		return "", false, fmt.Errorf("%w: record for mask is not base64: %v", ErrStore, err)
	}
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return "", false, fmt.Errorf("%w: record for mask is truncated", ErrStore)
	}
	plain, err := s.aead.Open(nil, sealed[:n], sealed[n:], []byte(mask))
	if err != nil {
		return "", false, fmt.Errorf("%w: decrypt failed: %v", ErrStore, err)
	}
	return string(plain), true, nil
}

// IsMask reports whether value is a mask this store minted, for any source.
// Used to avoid masking a mask.
func (s *Store) IsMask(value string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.byMask[value]
	return ok
}

// saveLocked writes every record to vault.json via a temp file and rename,
// so a crash mid-write never leaves a half-written vault. Caller holds s.mu.
func (s *Store) saveLocked() error {
	records := make([]storeRecord, 0, len(s.byMask))
	for _, r := range s.byMask {
		records = append(records, r)
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: encoding vault: %v", ErrStore, err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(s.vaultPath), ".vault-*.json")
	if err != nil {
		return fmt.Errorf("%w: creating temp vault file: %v", ErrStore, err)
	}
	tmpName := tmp.Name()
	// Remove the temp file on any failure below; after a successful rename
	// this is a no-op error we ignore.
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("%w: chmod temp vault file: %v", ErrStore, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("%w: writing temp vault file: %v", ErrStore, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("%w: syncing temp vault file: %v", ErrStore, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("%w: closing temp vault file: %v", ErrStore, err)
	}
	if err := os.Rename(tmpName, s.vaultPath); err != nil {
		return fmt.Errorf("%w: replacing vault file: %v", ErrStore, err)
	}
	return nil
}

const base62 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// sameShapeMask keeps the real token's prefix and length and randomises
// the rest, so the client (and any local format check) treats the mask
// exactly like a real token. A mask is recognised only by being in the
// store, never by a marker in the string.
func sameShapeMask(real, maskPrefix string) (string, error) {
	var prefix string
	switch {
	case maskPrefix != "":
		if !strings.HasPrefix(real, maskPrefix) {
			return "", fmt.Errorf("%w: mask_prefix %q does not match the token; refusing to mask", ErrStore, maskPrefix)
		}
		prefix = maskPrefix
	case strings.Contains(real, "_"):
		prefix = real[:strings.LastIndex(real, "_")+1]
	default:
		prefix = ""
	}
	bodyLen := len(real) - len(prefix)
	if bodyLen < 1 {
		return "", fmt.Errorf("%w: token has no body after its prefix; refusing to mask", ErrStore)
	}

	body := make([]byte, 0, bodyLen)
	buf := make([]byte, 1)
	for len(body) < bodyLen {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("%w: random: %v", ErrStore, err)
		}
		// Rejection sampling: 248 = 4*62, so b%62 is uniform below it.
		if buf[0] >= 248 {
			continue
		}
		body = append(body, base62[int(buf[0])%62])
	}
	return prefix + string(body), nil
}
