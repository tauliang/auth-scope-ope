// Package trust pins the AuthScope signing-key history OPE trusts when it
// opens a sealed launch envelope or verifies a signed execution receipt.
// The pin file carries the signing-root fingerprint plus the initial
// authenticated key history; later rotations are accepted only through
// statements chained to that root. OPE never fetches keys over the
// network at startup: trust comes from the vendored pin file, and any
// key not chained to the pinned root is rejected. A served key history
// fetched later (for receipt verification) replaces the set only when
// every key chains to the same pinned root fingerprint.
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
	"sync"
	"time"
)

// PinFormat is the only pin-file format this package accepts.
const PinFormat = "authscope-signing-keys/v1"

// RotationDomain is the domain string inside a signed rotation statement.
const RotationDomain = "authscope-signing-keys/rotation/v1"

// maxServedHistoryAge bounds how old a served signing-key history may be
// before the refresh flow rejects it as a replay risk.
const maxServedHistoryAge = 24 * time.Hour

// maxServedHistorySkew bounds how far in the future a served history's
// served_at timestamp may be before it is rejected.
const maxServedHistorySkew = 5 * time.Minute

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
	ValidUntil        string `json:"valid_until,omitempty"`
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

// keyRecord is one trusted key with its validity window. A zero
// validUntil means the key has no expiry.
type keyRecord struct {
	pub        ed25519.PublicKey
	validFrom  time.Time
	validUntil time.Time
}

// KeyStore is the verified set of AuthScope signing keys.
type KeyStore struct {
	// mu guards keys and keyIDs: the receipt worker and the HTTP
	// handler may verify concurrently while a refresh replaces the
	// set.
	mu          sync.RWMutex
	fingerprint string
	keys        map[string]keyRecord
	keyIDs      []string
}

// LoadSigningKeys reads, strictly decodes, and verifies a pin file. Every
// key must be Ed25519; the pinned root fingerprint must match the root
// entry; each non-root key must carry a rotation statement signed by an
// already-trusted predecessor. When expectedRootFingerprint is not empty
// it is an independent anchor for the root: the file's declared root
// fingerprint must equal it, so a wholesale pin-file swap fails closed.
// An empty expected fingerprint keeps the file itself as the root, whose
// digest is enforced by make contract-ready against the contract lock.
func LoadSigningKeys(path, expectedRootFingerprint string) (*KeyStore, error) {
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
	if expectedRootFingerprint != "" && doc.SigningRootFingerprint != expectedRootFingerprint {
		return nil, fmt.Errorf("trust: pin file root fingerprint does not match the expected root")
	}
	if len(doc.Keys) == 0 {
		return nil, fmt.Errorf("trust: pin file has no keys")
	}
	ks := &KeyStore{keys: make(map[string]keyRecord)}
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

func parseValidityWindow(keyID, validFrom, validUntil string) (from time.Time, until time.Time, err error) {
	from, err = time.Parse(time.RFC3339, validFrom)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("trust: key %q has bad valid_from: %w", keyID, err)
	}
	if validUntil != "" {
		until, err = time.Parse(time.RFC3339, validUntil)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("trust: key %q has bad valid_until: %w", keyID, err)
		}
		if !until.After(from) {
			return time.Time{}, time.Time{}, fmt.Errorf("trust: key %q valid_until is not after valid_from", keyID)
		}
	}
	return from, until, nil
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
	validFrom, validUntil, err := parseValidityWindow(k.KeyID, k.ValidFrom, k.ValidUntil)
	if err != nil {
		return err
	}
	rec := keyRecord{pub: ed25519.PublicKey(rawPub), validFrom: validFrom, validUntil: validUntil}
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
		ks.keys[k.KeyID] = rec
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
	prevPub := ks.keys[k.RotatedFrom].pub
	if !ed25519.Verify(prevPub, stmtRaw, sig) {
		return fmt.Errorf("trust: key %q rotation signature does not verify", k.KeyID)
	}
	ks.keys[k.KeyID] = rec
	ks.keyIDs = append(ks.keyIDs, k.KeyID)
	trusted[k.KeyID] = true
	return nil
}

// Fingerprint returns the pinned signing-root fingerprint.
func (ks *KeyStore) Fingerprint() string { return ks.fingerprint }

// KeyIDs returns the trusted key IDs in sorted order.
func (ks *KeyStore) KeyIDs() []string {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	out := make([]string, len(ks.keyIDs))
	copy(out, ks.keyIDs)
	return out
}

// VerifySignature verifies msg against the trusted key keyID.
func (ks *KeyStore) VerifySignature(keyID string, msg, sig []byte) error {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	rec, ok := ks.keys[keyID]
	if !ok {
		return fmt.Errorf("trust: unknown signing key %q", keyID)
	}
	if !ed25519.Verify(rec.pub, msg, sig) {
		return fmt.Errorf("trust: signature from key %q does not verify", keyID)
	}
	return nil
}

// KeyAt returns the trusted public key for keyID as it was at time at.
// A key is usable only inside its validity window: valid_from on or
// before at, and valid_until (when set) strictly after at. Unknown,
// not-yet-valid, and expired keys fail closed.
func (ks *KeyStore) KeyAt(keyID string, at time.Time) (ed25519.PublicKey, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	rec, ok := ks.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("trust: unknown signing key %q", keyID)
	}
	if at.Before(rec.validFrom) {
		return nil, fmt.Errorf("trust: signing key %q not yet valid at %s", keyID, at.UTC().Format(time.RFC3339))
	}
	if !rec.validUntil.IsZero() && !at.Before(rec.validUntil) {
		return nil, fmt.Errorf("trust: signing key %q expired at %s", keyID, rec.validUntil.UTC().Format(time.RFC3339))
	}
	return rec.pub, nil
}

// ServedKey is one key entry from the served signing-key history. Only
// Ed25519 keys are accepted. ValidFrom and ValidUntil are unix seconds;
// zero means the bound is unknown (valid from the beginning of time, or
// no expiry). RotatedFrom names the predecessor key ID, empty for the
// root.
type ServedKey struct {
	KeyID       string
	PublicKey   string
	ValidFrom   int64
	ValidUntil  int64
	RotatedFrom string
}

// RefreshFromHistory replaces the key set with a served signing-key
// history. The refresh is accepted only when every key carries valid
// Ed25519 material and chains through rotated_from to a key whose
// fingerprint equals the pinned root fingerprint: the pinned root is
// the trust anchor for refreshed history too. The served_at timestamp
// must be recent (bounded staleness defeats history replay) and not in
// the future. On any failure the previous key set is left untouched.
//
// Note: the locked upstream history schema carries rotated_from ids
// but no per-rotation signatures, so the chain check ties each key's
// ancestry to the pinned root key material but cannot cryptographically
// prove the root authorized each hop. A forged rotation from the pinned
// root id would pass the chain walk; this is an inherent limit of the
// locked schema, not a gap in the check. The initial pin file keys are
// fully signature-verified, and histories arrive over the workspace's
// mutual-TLS connection.
func (ks *KeyStore) RefreshFromHistory(keys []ServedKey, servedAt, now time.Time) error {
	if len(keys) == 0 {
		return fmt.Errorf("trust: refreshed history has no keys")
	}
	if servedAt.IsZero() {
		return fmt.Errorf("trust: refreshed history has no served_at")
	}
	if age := now.Sub(servedAt); age > maxServedHistoryAge {
		return fmt.Errorf("trust: refreshed history is stale (served %s ago)", age.Truncate(time.Second))
	}
	if servedAt.After(now.Add(maxServedHistorySkew)) {
		return fmt.Errorf("trust: refreshed history served_at is in the future")
	}
	parsed := make(map[string]keyRecord, len(keys))
	byID := make(map[string]ServedKey, len(keys))
	order := make([]string, 0, len(keys))
	for _, k := range keys {
		if k.KeyID == "" {
			return fmt.Errorf("trust: refreshed key with empty id")
		}
		if _, dup := parsed[k.KeyID]; dup {
			return fmt.Errorf("trust: refreshed history has duplicate key id %q", k.KeyID)
		}
		rawPub, err := base64.RawURLEncoding.DecodeString(k.PublicKey)
		if err != nil {
			return fmt.Errorf("trust: refreshed key %q has bad public key: %w", k.KeyID, err)
		}
		if len(rawPub) != ed25519.PublicKeySize {
			return fmt.Errorf("trust: refreshed key %q has %d-byte public key", k.KeyID, len(rawPub))
		}
		var validFrom, validUntil time.Time
		if k.ValidFrom != 0 {
			validFrom = time.Unix(k.ValidFrom, 0).UTC()
		}
		if k.ValidUntil != 0 {
			validUntil = time.Unix(k.ValidUntil, 0).UTC()
			if !validUntil.After(validFrom) {
				return fmt.Errorf("trust: refreshed key %q valid_until is not after valid_from", k.KeyID)
			}
		}
		parsed[k.KeyID] = keyRecord{
			pub:        ed25519.PublicKey(rawPub),
			validFrom:  validFrom,
			validUntil: validUntil,
		}
		byID[k.KeyID] = k
		order = append(order, k.KeyID)
	}
	// Every key must chain to the pinned root fingerprint.
	for _, k := range keys {
		seen := make(map[string]bool)
		cur := k.KeyID
		for {
			if seen[cur] {
				return fmt.Errorf("trust: refreshed history has a rotation cycle at %q", cur)
			}
			seen[cur] = true
			sum := sha256.Sum256(parsed[cur].pub)
			if "sha256:"+hex.EncodeToString(sum[:]) == ks.fingerprint {
				break
			}
			prevID := byID[cur].RotatedFrom
			if prevID == "" {
				return fmt.Errorf("trust: refreshed key %q does not chain to the pinned root", k.KeyID)
			}
			if _, ok := parsed[prevID]; !ok {
				return fmt.Errorf("trust: refreshed key %q rotates from unknown key %q", k.KeyID, prevID)
			}
			cur = prevID
		}
	}
	ks.mu.Lock()
	ks.keys = parsed
	ks.keyIDs = order
	sort.Strings(ks.keyIDs)
	ks.mu.Unlock()
	return nil
}
