package e2e

// Transport security: workload transport authentication rejects unknown
// keys, broken signatures, stale timestamps, and workspace headers that
// do not match the identity's workspace.

import (
	"strings"
	"testing"
	"time"
)

func TestTransportSecurity(t *testing.T) {
	f := newJourneyFixture(t, nil)
	body := map[string]any{"ping": true}

	t.Run("missing_auth", func(t *testing.T) {
		status, raw := f.doRawWithHeaders("GET", "/v1/discovery", nil, f.now,
			map[string]string{
				"X-AuthScope-Workload-KeyID":     "",
				"X-AuthScope-Workload-Timestamp": "",
				"X-AuthScope-Workload-Signature": "",
				"X-AuthScope-Workspace":          "",
			})
		if status != 401 {
			t.Fatalf("missing auth: status %d, want 401: %s", status, raw)
		}
		mustContainCode(t, raw, "missing_workload_auth")
	})

	t.Run("unknown_key", func(t *testing.T) {
		status, raw := f.doRawWithHeaders("GET", "/v1/discovery", nil, f.now,
			map[string]string{"X-AuthScope-Workload-KeyID": "key-unknown"})
		if status != 401 {
			t.Fatalf("unknown key: status %d, want 401: %s", status, raw)
		}
		mustContainCode(t, raw, "unknown_workload_key")
	})

	t.Run("tampered_signature", func(t *testing.T) {
		// 86 base64 chars decode to 64 zero bytes: well-formed, wrong key.
		status, raw := f.doRawWithHeaders("POST", "/v1/mission-proposals/shape", body, f.now,
			map[string]string{"X-AuthScope-Workload-Signature": strings.Repeat("A", 86)})
		if status != 401 {
			t.Fatalf("tampered signature: status %d, want 401: %s", status, raw)
		}
		mustContainCode(t, raw, "invalid_workload_signature")
	})

	t.Run("stale_timestamp", func(t *testing.T) {
		status, raw := f.doRawWithHeaders("GET", "/v1/discovery", nil, f.now.Add(-time.Hour), nil)
		if status != 401 {
			t.Fatalf("stale timestamp: status %d, want 401: %s", status, raw)
		}
		mustContainCode(t, raw, "stale_workload_timestamp")
	})

	t.Run("future_timestamp", func(t *testing.T) {
		status, raw := f.doRawWithHeaders("GET", "/v1/discovery", nil, f.now.Add(time.Hour), nil)
		if status != 401 {
			t.Fatalf("future timestamp: status %d, want 401: %s", status, raw)
		}
		mustContainCode(t, raw, "stale_workload_timestamp")
	})

	t.Run("workspace_header_mismatch", func(t *testing.T) {
		status, raw := f.doRawWithHeaders("GET", "/v1/discovery", nil, f.now,
			map[string]string{"X-AuthScope-Workspace": "ws-attacker"})
		if status != 401 {
			t.Fatalf("workspace mismatch: status %d, want 401: %s", status, raw)
		}
		mustContainCode(t, raw, "workspace_mismatch")
	})

	t.Run("workspace_header_absent_fails_closed", func(t *testing.T) {
		status, raw := f.doRawWithHeaders("GET", "/v1/discovery", nil, f.now,
			map[string]string{"X-AuthScope-Workspace": ""})
		if status != 401 {
			t.Fatalf("absent workspace header: status %d, want 401: %s", status, raw)
		}
		mustContainCode(t, raw, "workspace_mismatch")
	})
}
