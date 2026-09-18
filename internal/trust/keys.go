// Package trust pins the AuthScope signing-key history OPE trusts when it
// opens a sealed launch envelope. The pin file carries the signing-root
// fingerprint plus the initial authenticated key history; later rotations
// are accepted only through statements chained to that root. OPE never
// fetches keys over the network: trust comes from the vendored pin file,
// and any key not chained to the pinned root is rejected.
package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

// PinFormat is the only pin-file format this package accepts.
const PinFormat = "authscope-signing-keys/v1"

// RotationDomain is the domain string inside a signed rotation statement.
const RotationDomain = "authscope-signing-keys/rotation/v1"

type pinFile struct {
	Format                 string   `json:"format"`
	Note                   string   `json:"note"`
	SigningRootFingerprint string   `json:"signing_root_fingerprint"`
	Keys                   []pinKey `json:"keys"`
}

type pinKey struct {
	KeyID             string `json:"key_id"`
	Algorithm         string `json:"algorithm"`
	PublicKey         string `json:"public_key"`
	ValidFrom         string `json:"valid_from"`
	Root              bool   `json:"root"`
	RotatedFrom       string `json:"rotated_from"`
	RotationStatement string `json:"rotation_statement"`
	RotationSignature string `json:"rotation_signature"`
}

type rotationStatement struct {
	Domain        string `json:"domain"`
	PreviousKeyID string `json:"previous_key_id"`
	NewKeyID      string `json:"new_key_id"`
	NewPublicKey  string `json:"new_public_key"`
	IssuedAt      string `json:"issued_at"`
}

// KeyStore is the verified set of AuthScope signing keys.
type KeyStore struct {
	fingerprint string
	keys        map[string]ed25519.PublicKey
	keyIDs      []string
}

// LoadSigningKeys reads, strictly decodes, and verifies a pin file. Every
// key must be Ed25519; the pinned root fingerprint must match the root
// entry; each non-root key must carry a rotation statement signed by an
// already-trusted predecessor.
func LoadSigningKeys(path string) (*KeyStore, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("trust: read pin file: %w", err)
	}
	var doc pinFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("trust: decode pin file: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("trust: pin file has trailing data")
	}
	if doc.Format != PinFormat {
		return nil, fmt.Errorf("trust: unsupported pin format %q", doc.Format)
	}
	if len(doc.Keys) == 0 {
		return nil, fmt.Errorf("trust: pin file has no keys")
	}
	ks := &KeyStore{keys: make(map[string]ed25519.PublicKey)}
	trusted := make(map[string]bool)
	for i := range doc.Keys {
		if err := ks.addKey(doc.Keys[i], trusted, doc.SigningRootFingerprint); err != nil {
			return nil, err
		}
	}
	if ks.fingerprint == "" {
		return nil, fmt.Errorf("trust: pin file has no root key")
	}
	if ks.fingerprint != doc.SigningRootFingerprint {
		return nil, fmt.Errorf("trust: root fingerprint mismatch")
	}
	sort.Strings(ks.keyIDs)
	return ks, nil
}

func (ks *KeyStore) addKey(k pinKey, trusted map[string]bool, pinnedFingerprint string) error {
	if k.KeyID == "" {
		return fmt.Errorf("trust: key with empty id")
	}
	if _, dup := ks.keys[k.KeyID]; dup {
		return fmt.Errorf("trust: duplicate key id %q", k.KeyID)
	}
	if k.Algorithm != "Ed25519" {
		return fmt.Errorf("trust: key %q uses unsupported algorithm %q", k.KeyID, k.Algorithm)
	}
	rawPub, err := base64.RawURLEncoding.DecodeString(k.PublicKey)
	if err != nil {
		return fmt.Errorf("trust: key %q has bad public key: %w", k.KeyID, err)
	}
	if len(rawPub) != ed25519.PublicKeySize {
		return fmt.Errorf("trust: key %q has %d-byte public key", k.KeyID, len(rawPub))
	}
	if k.ValidFrom == "" {
		return fmt.Errorf("trust: key %q has no valid_from", k.KeyID)
	}
	if _, err := time.Parse(time.RFC3339, k.ValidFrom); err != nil {
		return fmt.Errorf("trust: key %q has bad valid_from: %w", k.KeyID, err)
	}
	if k.Root {
		sum := sha256.Sum256(rawPub)
		fp := "sha256:" + hex.EncodeToString(sum[:])
		if fp != pinnedFingerprint {
			return fmt.Errorf("trust: root key %q does not match pinned fingerprint", k.KeyID)
		}
		if ks.fingerprint != "" {
			return fmt.Errorf("trust: more than one root key")
		}
		ks.fingerprint = fp
		ks.keys[k.KeyID] = ed25519.PublicKey(rawPub)
		ks.keyIDs = append(ks.keyIDs, k.KeyID)
		trusted[k.KeyID] = true
		return nil
	}
	// Non-root keys must chain to an already-trusted predecessor. The pin
	// file lists keys in trust order: root first, then each successor.
	prev, ok := trusted[k.RotatedFrom]
	if !ok || !prev {
		return fmt.Errorf("trust: key %q rotates from untrusted key %q", k.KeyID, k.RotatedFrom)
	}
	stmtRaw, err := base64.RawURLEncoding.DecodeString(k.RotationStatement)
	if err != nil {
		return fmt.Errorf("trust: key %q has bad rotation statement: %w", k.KeyID, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(k.RotationSignature)
	if err != nil {
		return fmt.Errorf("trust: key %q has bad rotation signature: %w", k.KeyID, err)
	}
	var stmt rotationStatement
	sdec := json.NewDecoder(bytes.NewReader(stmtRaw))
	sdec.DisallowUnknownFields()
	if err := sdec.Decode(&stmt); err != nil {
		return fmt.Errorf("trust: key %q rotation statement does not decode: %w", k.KeyID, err)
	}
	var extra any
	if err := sdec.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trust: key %q rotation statement has trailing data", k.KeyID)
	}
	if stmt.Domain != RotationDomain {
		return fmt.Errorf("trust: key %q rotation domain %q", k.KeyID, stmt.Domain)
	}
	if stmt.PreviousKeyID != k.RotatedFrom {
		return fmt.Errorf("trust: key %q rotation names previous key %q, want %q", k.KeyID, stmt.PreviousKeyID, k.RotatedFrom)
	}
	if stmt.NewKeyID != k.KeyID {
		return fmt.Errorf("trust: key %q rotation names new key %q", k.KeyID, stmt.NewKeyID)
	}
	if stmt.NewPublicKey != k.PublicKey {
		return fmt.Errorf("trust: key %q rotation names a different public key", k.KeyID)
	}
	if _, err := time.Parse(time.RFC3339, stmt.IssuedAt); err != nil {
		return fmt.Errorf("trust: key %q rotation has bad issued_at: %w", k.KeyID, err)
	}
	prevPub := ks.keys[k.RotatedFrom]
	if !ed25519.Verify(prevPub, stmtRaw, sig) {
		return fmt.Errorf("trust: key %q rotation signature does not verify", k.KeyID)
	}
	ks.keys[k.KeyID] = ed25519.PublicKey(rawPub)
	ks.keyIDs = append(ks.keyIDs, k.KeyID)
	trusted[k.KeyID] = true
	return nil
}

// Fingerprint returns the pinned signing-root fingerprint.
func (ks *KeyStore) Fingerprint() string { return ks.fingerprint }

// KeyIDs returns the trusted key IDs in sorted order.
func (ks *KeyStore) KeyIDs() []string {
	out := make([]string, len(ks.keyIDs))
	copy(out, ks.keyIDs)
	return out
}

// VerifySignature verifies msg against the trusted key keyID.
func (ks *KeyStore) VerifySignature(keyID string, msg, sig []byte) error {
	pub, ok := ks.keys[keyID]
	if !ok {
		return fmt.Errorf("trust: unknown signing key %q", keyID)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("trust: signature from key %q does not verify", keyID)
	}
	return nil
}
