package cli_test

// Tests for the token exchange client and the envelope opening: the CLI
// posts only the code and verifier, decodes the sealed envelope, and
// opens it against the pinned signing keys and the retained
// authorization values.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/cli"
	"github.com/tauliang/authscope-ope/internal/launch"
	"github.com/tauliang/authscope-ope/internal/trust"
)

// setBundleField sets an unexported LaunchAuthorization field in tests.
func setBundleField(t *testing.T, bundle *cli.LaunchAuthorization, field string, value any) {
	t.Helper()
	v := reflect.ValueOf(bundle).Elem().FieldByName(field)
	if !v.IsValid() {
		t.Fatalf("no field %q", field)
	}
	reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().Set(reflect.ValueOf(value))
}

func writeRootPinFile(t *testing.T, id string, pub ed25519.PublicKey) string {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	sum := sha256.Sum256(pub)
	doc := map[string]any{
		"format":                   "authscope-signing-keys/v1",
		"signing_root_fingerprint": "sha256:" + hex.EncodeToString(sum[:]),
		"keys": []any{
			map[string]any{
				"key_id":     id,
				"algorithm":  "Ed25519",
				"public_key": base64.RawURLEncoding.EncodeToString(pub),
				"valid_from": now.Format(time.RFC3339),
				"root":       true,
			},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signing-keys.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// sealTestEnvelope seals a payload whose binding values match the
// returned bundle fields.
func sealTestEnvelope(t *testing.T, runnerExe string) (sealed []byte, bundle *cli.LaunchAuthorization, keys *trust.KeyStore) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys, err = trust.LoadSigningKeys(writeRootPinFile(t, "root-1", pub))
	if err != nil {
		t.Fatal(err)
	}
	cliPriv, cliPub, err := authn.EphemeralX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	args := []string{"--mission", "m-1"}
	payload := launch.LaunchPayload{
		Audience:         launch.EnvelopeAudience,
		RunID:            "run-test-1",
		MissionRef:       "mission-01",
		MissionVersion:   3,
		ProposalDigest:   "sha256:proposal",
		InvocationDigest: authn.InvocationDigestForLaunch("kit-a", "1.0.0", args),
		RuntimePolicyID:  "rp-01",
		LeaseID:          "lease-01",
		AgentKitID:       "kit-a",
		AgentKitVersion:  "1.0.0",
		RunnerExecutable: runnerExe,
		RunnerArguments:  args,
		IsolationProfile: launch.IsolationEnforced,
		Nonce:            base64.RawURLEncoding.EncodeToString(nonce),
		IssuedAt:         now.Add(-time.Minute).Unix(),
		ExpiresAt:        now.Add(time.Hour).Unix(),
	}
	sealed, err = launch.SealEnvelope(payload, priv, "root-1", cliPub)
	if err != nil {
		t.Fatal(err)
	}
	bundle = &cli.LaunchAuthorization{
		AuthorizationID:  "authz-1",
		PassID:           "pass-1",
		ProposalDigest:   "sha256:proposal",
		AgentKitID:       "kit-a",
		AgentKitVersion:  "1.0.0",
		RunnerArguments:  append([]string{}, args...),
		InvocationDigest: payload.InvocationDigest,
		Code:             "code-1",
	}
	setBundleField(t, bundle, "ephemeralPrivateKey", cliPriv)
	return sealed, bundle, keys
}

func TestOpenSealedEnvelope(t *testing.T) {
	sealed, bundle, keys := sealTestEnvelope(t, "/opt/runners/agent-run")
	defer bundle.Destroy()
	payload, signed, err := bundle.OpenSealedEnvelope(sealed, keys, "/opt/runners/agent-run")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if payload.RunID != "run-test-1" {
		t.Fatalf("run id = %q", payload.RunID)
	}
	if len(signed) == 0 {
		t.Fatal("signed envelope bytes missing")
	}
}

func TestOpenSealedEnvelopeRejectsWrongRunner(t *testing.T) {
	sealed, bundle, keys := sealTestEnvelope(t, "/opt/runners/agent-run")
	defer bundle.Destroy()
	if _, _, err := bundle.OpenSealedEnvelope(sealed, keys, "/opt/runners/other-run"); err == nil {
		t.Fatal("expected error for mismatched runner executable")
	}
}

func TestOpenSealedEnvelopeRejectsTampered(t *testing.T) {
	sealed, bundle, keys := sealTestEnvelope(t, "/opt/runners/agent-run")
	defer bundle.Destroy()
	sealed[len(sealed)-1] ^= 0xff
	if _, _, err := bundle.OpenSealedEnvelope(sealed, keys, "/opt/runners/agent-run"); err == nil {
		t.Fatal("expected error for tampered envelope")
	}
}

func TestExchangeLaunch(t *testing.T) {
	sealedB64 := base64.RawURLEncoding.EncodeToString([]byte("sealed-bytes"))
	var gotCode, gotVerifier string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cli/token" {
			http.NotFound(w, r)
			return
		}
		var req struct {
			Code     string `json:"code"`
			Verifier string `json:"verifier"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
		}
		gotCode, gotVerifier = req.Code, req.Verifier
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"run_id":"run-9","mission_ref":"mission-01","sealed_envelope":"` + sealedB64 + `"}`))
	}))
	defer srv.Close()
	bundle := &cli.LaunchAuthorization{Code: "code-9"}
	setBundleField(t, bundle, "verifier", []byte("verifier-9"))
	defer bundle.Destroy()
	ex, err := cli.ExchangeLaunch(context.Background(), srv.URL, bundle, srv.Client())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if gotCode != "code-9" || gotVerifier != base64.RawURLEncoding.EncodeToString([]byte("verifier-9")) {
		t.Fatalf("server saw code %q verifier %q", gotCode, gotVerifier)
	}
	if ex.RunID != "run-9" || string(ex.SealedEnvelope) != "sealed-bytes" {
		t.Fatalf("unexpected exchange: %+v", ex)
	}
}

func TestExchangeLaunchSurfacesProblem(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"type":"about:blank","title":"authorization expired","status":410,"detail":"The launch authorization is no longer valid; authorize again in the browser."}`))
	}))
	defer srv.Close()
	bundle := &cli.LaunchAuthorization{Code: "code-9"}
	setBundleField(t, bundle, "verifier", []byte("verifier-9"))
	defer bundle.Destroy()
	_, err := cli.ExchangeLaunch(context.Background(), srv.URL, bundle, srv.Client())
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); !strings.Contains(got, "authorization expired") {
		t.Fatalf("error %q does not surface the problem title", got)
	}
}
