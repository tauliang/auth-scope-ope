package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestBindInstanceCreatesSingleDurableRecord(t *testing.T) {
	db := openTestStore(t)
	rec := testInstance("inst-1")
	bindTestInstance(t, db, rec)

	got, err := db.GetInstance(context.Background())
	if err != nil {
		t.Fatalf("GetInstance: %v", err)
	}
	if got.InstanceID != rec.InstanceID || got.WorkspaceID != rec.WorkspaceID ||
		got.Hostname != rec.Hostname || got.Origin != rec.Origin ||
		got.RPID != rec.RPID || got.SessionCookieName != rec.SessionCookieName {
		t.Fatalf("binding mismatch: got %+v want %+v", got, rec)
	}
	if got.WorkloadIdentityDigest != "" {
		t.Fatalf("digest must start empty, got %q", got.WorkloadIdentityDigest)
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("CreatedAt must be set")
	}

	// Rebinding with identical values is idempotent.
	bindTestInstance(t, db, rec)
}

func TestBindInstanceRejectsRebindOnAnyBindingFieldChange(t *testing.T) {
	base := testInstance("inst-1")

	cases := []struct {
		name   string
		mutate func(InstanceRecord) InstanceRecord
	}{
		// The session cookie name derives from the instance ID, so a
		// cookie-name change always arrives with an instance-ID change.
		{"instance id and cookie name", func(r InstanceRecord) InstanceRecord {
			r.InstanceID = "inst-2"
			r.SessionCookieName = DeriveSessionCookieName("inst-2")
			return r
		}},
		{"workspace", func(r InstanceRecord) InstanceRecord { r.WorkspaceID = "ws-other"; return r }},
		{"hostname", func(r InstanceRecord) InstanceRecord { r.Hostname = "other.example.com"; return r }},
		{"origin", func(r InstanceRecord) InstanceRecord {
			r.Origin = "https://other.example.com"
			r.RPID = "other.example.com"
			return r
		}},
		{"rp id", func(r InstanceRecord) InstanceRecord { r.RPID = "example.com"; return r }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := openTestStore(t)
			bindTestInstance(t, db, base)
			ctx := context.Background()
			err := db.WithTx(ctx, func(tx Tx) error {
				return tx.BindInstance(ctx, tc.mutate(base))
			})
			if !errors.Is(err, ErrInstanceRebind) {
				t.Fatalf("BindInstance error = %v, want ErrInstanceRebind", err)
			}
		})
	}
}

func TestDeriveSessionCookieName(t *testing.T) {
	if got := DeriveSessionCookieName("abc123"); got != "__Host-authscope-ope-session-abc123" {
		t.Fatalf("cookie name = %q", got)
	}
}

func TestValidateInstanceRejectsBadHostname(t *testing.T) {
	for _, host := range []string{"", "not a host!", "-leading.example.com", "trailing-.example.com", strings.Repeat("a", 300)} {
		rec := testInstance("inst-1")
		rec.Hostname = host
		if err := ValidateInstance(rec, "development"); !errors.Is(err, ErrInvalidHostname) {
			t.Fatalf("hostname %q: error = %v, want ErrInvalidHostname", host, err)
		}
	}
}

func TestValidateInstanceRejectsBadOrigin(t *testing.T) {
	// Release mode requires exact HTTPS.
	rec := testInstance("inst-1")
	rec.Origin = "http://ope.example.com"
	if err := ValidateInstance(rec, "release"); !errors.Is(err, ErrInsecureOrigin) {
		t.Fatalf("release http origin: error = %v, want ErrInsecureOrigin", err)
	}

	// Development allows HTTPS and loopback HTTP only.
	rec.Origin = "http://127.0.0.1:8080"
	rec.RPID = "127.0.0.1"
	if err := ValidateInstance(rec, "development"); err != nil {
		t.Fatalf("development loopback http origin: error = %v", err)
	}
	rec.Origin = "http://localhost:8080"
	rec.RPID = "localhost"
	if err := ValidateInstance(rec, "development"); err != nil {
		t.Fatalf("development localhost http origin: error = %v", err)
	}

	// Non-loopback HTTP is rejected even in development.
	rec.Origin = "http://ope.example.com"
	rec.RPID = "ope.example.com"
	if err := ValidateInstance(rec, "development"); !errors.Is(err, ErrOriginNotPermitted) {
		t.Fatalf("development non-loopback http origin: error = %v, want ErrOriginNotPermitted", err)
	}

	// Origins with paths, queries, or userinfo are not exact origins.
	for _, origin := range []string{"https://ope.example.com/app", "https://ope.example.com?a=b", "https://user@ope.example.com", "ftp://ope.example.com", "ope.example.com"} {
		rec.Origin = origin
		if err := ValidateInstance(rec, "development"); !errors.Is(err, ErrInvalidOrigin) {
			t.Fatalf("origin %q: error = %v, want ErrInvalidOrigin", origin, err)
		}
	}
}

func TestValidateInstanceRejectsRPIDMismatch(t *testing.T) {
	rec := testInstance("inst-1")
	rec.RPID = "unrelated.example.org"
	if err := ValidateInstance(rec, "development"); !errors.Is(err, ErrRPIDOriginMismatch) {
		t.Fatalf("error = %v, want ErrRPIDOriginMismatch", err)
	}
	// A parent domain of the origin host is a valid RP ID.
	rec.RPID = "example.com"
	if err := ValidateInstance(rec, "development"); err != nil {
		t.Fatalf("parent domain RP ID: error = %v", err)
	}
	// IP literals and empty values are not valid RP IDs.
	for _, rpid := range []string{"", "127.0.0.1", "https://ope.example.com"} {
		rec.RPID = rpid
		if err := ValidateInstance(rec, "development"); !errors.Is(err, ErrInvalidRPID) && !errors.Is(err, ErrRPIDOriginMismatch) {
			t.Fatalf("rpid %q: error = %v, want ErrInvalidRPID or ErrRPIDOriginMismatch", rpid, err)
		}
	}
}

func TestValidateInstanceRejectsWrongCookieName(t *testing.T) {
	rec := testInstance("inst-1")
	rec.SessionCookieName = "__Host-authscope-ope-session-other"
	if err := ValidateInstance(rec, "development"); !errors.Is(err, ErrInvalidCookieName) {
		t.Fatalf("error = %v, want ErrInvalidCookieName", err)
	}
}

func TestAttachWorkloadIdentityExactlyOnce(t *testing.T) {
	db := openTestStore(t)
	bindTestInstance(t, db, testInstance("inst-1"))
	ctx := context.Background()

	if err := db.WithTx(ctx, func(tx Tx) error {
		return tx.AttachWorkloadIdentity(ctx, "", "sha256:digest-1")
	}); err != nil {
		t.Fatalf("first attach: %v", err)
	}
	got, err := db.GetInstance(ctx)
	if err != nil {
		t.Fatalf("GetInstance: %v", err)
	}
	if got.WorkloadIdentityDigest != "sha256:digest-1" {
		t.Fatalf("digest = %q", got.WorkloadIdentityDigest)
	}

	// No path may replace the digest once attached.
	err = db.WithTx(ctx, func(tx Tx) error {
		return tx.AttachWorkloadIdentity(ctx, "", "sha256:digest-2")
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("second attach error = %v, want ErrConflict", err)
	}
}

func TestGetInstanceReturnsNotFoundBeforeBind(t *testing.T) {
	db := openTestStore(t)
	_, err := db.GetInstance(context.Background())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

func TestBindInstanceCreatedAtPreserved(t *testing.T) {
	db := openTestStore(t)
	rec := testInstance("inst-1")
	created := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	rec.CreatedAt = created
	bindTestInstance(t, db, rec)
	got, err := db.GetInstance(context.Background())
	if err != nil {
		t.Fatalf("GetInstance: %v", err)
	}
	if !got.CreatedAt.Equal(created) {
		t.Fatalf("CreatedAt = %v, want %v", got.CreatedAt, created)
	}
}
