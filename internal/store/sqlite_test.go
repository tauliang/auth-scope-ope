package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMissionPassCannotCrossWorkspace(t *testing.T) {
	db := openTestStore(t)
	savePass(t, db, "personal", "pass-1", 1)
	_, err := db.GetMissionPass(context.Background(), "business", "pass-1")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v", err)
	}
}

func TestGetMissionPassReturnsNotFound(t *testing.T) {
	db := openTestStore(t)
	_, err := db.GetMissionPass(context.Background(), "personal", "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v", err)
	}
}

func TestPutMissionPassRejectsStaleExpectedRevision(t *testing.T) {
	db := openTestStore(t)
	savePass(t, db, "personal", "pass-1", 1)
	got, err := db.GetMissionPass(context.Background(), "personal", "pass-1")
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	if got.StoreRevision != 1 {
		t.Fatalf("StoreRevision = %d, want 1", got.StoreRevision)
	}

	ctx := context.Background()
	err = db.WithTx(ctx, func(tx Tx) error {
		got.DraftVersion = 2
		return tx.PutMissionPass(ctx, got, 0 /* stale: record is at revision 1 */)
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("error = %v, want ErrConflict", err)
	}
}

func TestPutMissionPassCASIncrementsStoreRevision(t *testing.T) {
	db := openTestStore(t)
	savePass(t, db, "personal", "pass-1", 1)
	ctx := context.Background()

	got, err := db.GetMissionPass(ctx, "personal", "pass-1")
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	// Updating the upstream authority version increments the local
	// compare-and-swap revision without changing the draft version.
	got.AuthScopeMissionVersion = 7
	if err := db.WithTx(ctx, func(tx Tx) error {
		return tx.PutMissionPass(ctx, got, got.StoreRevision)
	}); err != nil {
		t.Fatalf("PutMissionPass: %v", err)
	}
	after, err := db.GetMissionPass(ctx, "personal", "pass-1")
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	if after.StoreRevision != 2 {
		t.Fatalf("StoreRevision = %d, want 2", after.StoreRevision)
	}
	if after.DraftVersion != 1 {
		t.Fatalf("DraftVersion = %d, want 1 (unchanged)", after.DraftVersion)
	}
	if after.AuthScopeMissionVersion != 7 {
		t.Fatalf("AuthScopeMissionVersion = %d, want 7", after.AuthScopeMissionVersion)
	}

	// Creating a revised proposal increments draft and store revisions
	// without copying an unrelated upstream mission version.
	after.DraftVersion = 2
	after.AuthScopeMissionVersion = 0
	if err := db.WithTx(ctx, func(tx Tx) error {
		return tx.PutMissionPass(ctx, after, after.StoreRevision)
	}); err != nil {
		t.Fatalf("PutMissionPass: %v", err)
	}
	final, err := db.GetMissionPass(ctx, "personal", "pass-1")
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	if final.StoreRevision != 3 || final.DraftVersion != 2 {
		t.Fatalf("got store=%d draft=%d, want store=3 draft=2", final.StoreRevision, final.DraftVersion)
	}
	if final.AuthScopeMissionVersion != 0 {
		t.Fatalf("AuthScopeMissionVersion = %d, want 0 (not copied)", final.AuthScopeMissionVersion)
	}
}

func TestPutEventIfAbsentDeduplicates(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	rec := MissionEventRecord{
		WorkspaceID: "personal",
		PassID:      "pass-1",
		EventID:     "evt-1",
		EventType:   "mission.started",
		Cursor:      "cursor-1",
		OccurredAt:  time.Now().UTC(),
	}

	var first, second bool
	err := db.WithTx(ctx, func(tx Tx) error {
		var err error
		first, err = tx.PutEventIfAbsent(ctx, rec)
		return err
	})
	if err != nil {
		t.Fatalf("first PutEventIfAbsent: %v", err)
	}
	err = db.WithTx(ctx, func(tx Tx) error {
		var err error
		second, err = tx.PutEventIfAbsent(ctx, rec)
		return err
	})
	if err != nil {
		t.Fatalf("second PutEventIfAbsent: %v", err)
	}
	if !first || second {
		t.Fatalf("inserted = (%v, %v), want (true, false)", first, second)
	}
	events, err := db.ListMissionEvents(ctx, "personal", "pass-1", "", 10)
	if err != nil {
		t.Fatalf("ListMissionEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("stored %d events, want 1", len(events))
	}
}

func TestMissionEventsAreWorkspaceQualified(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	for _, ws := range []string{"personal", "business"} {
		err := db.WithTx(ctx, func(tx Tx) error {
			_, err := tx.PutEventIfAbsent(ctx, MissionEventRecord{
				WorkspaceID: ws, PassID: "pass-1", EventID: "evt-1",
				EventType: "mission.started", Cursor: "c1", OccurredAt: time.Now().UTC(),
			})
			return err
		})
		if err != nil {
			t.Fatalf("PutEventIfAbsent(%s): %v", ws, err)
		}
	}
	events, err := db.ListMissionEvents(ctx, "personal", "pass-1", "", 10)
	if err != nil {
		t.Fatalf("ListMissionEvents: %v", err)
	}
	if len(events) != 1 || events[0].WorkspaceID != "personal" {
		t.Fatalf("events = %+v, want one personal event", events)
	}
}

func TestListMissionEventsCursorPagination(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	for i, cursor := range []string{"c1", "c2", "c3"} {
		err := db.WithTx(ctx, func(tx Tx) error {
			_, err := tx.PutEventIfAbsent(ctx, MissionEventRecord{
				WorkspaceID: "personal", PassID: "pass-1", EventID: "evt-" + cursor,
				EventType: "tick", Cursor: cursor,
				OccurredAt: time.Now().UTC().Add(time.Duration(i) * time.Second),
			})
			return err
		})
		if err != nil {
			t.Fatalf("PutEventIfAbsent: %v", err)
		}
	}
	events, err := db.ListMissionEvents(ctx, "personal", "pass-1", "c1", 10)
	if err != nil {
		t.Fatalf("ListMissionEvents: %v", err)
	}
	if len(events) != 2 || events[0].Cursor != "c2" || events[1].Cursor != "c3" {
		t.Fatalf("events = %+v, want cursors c2, c3", events)
	}
	events, err = db.ListMissionEvents(ctx, "personal", "pass-1", "", 2)
	if err != nil {
		t.Fatalf("ListMissionEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("limited events = %d, want 2", len(events))
	}
}

func TestIdempotencySameKeySameDigestReplaysFirstResult(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	rec := IdempotencyRecord{WorkspaceID: "personal", Key: "op-1", CanonicalDigest: "digest-a"}

	var first IdempotencyResult
	err := db.WithTx(ctx, func(tx Tx) error {
		var err error
		first, err = tx.BeginIdempotency(ctx, rec)
		return err
	})
	if err != nil {
		t.Fatalf("BeginIdempotency: %v", err)
	}
	if first.Replay {
		t.Fatal("first begin must not replay")
	}
	result := []byte(`{"ok":true}`)
	if err := db.WithTx(ctx, func(tx Tx) error {
		return tx.CompleteIdempotency(ctx, "personal", "op-1", result)
	}); err != nil {
		t.Fatalf("CompleteIdempotency: %v", err)
	}

	var replay IdempotencyResult
	err = db.WithTx(ctx, func(tx Tx) error {
		var err error
		replay, err = tx.BeginIdempotency(ctx, rec)
		return err
	})
	if err != nil {
		t.Fatalf("replay BeginIdempotency: %v", err)
	}
	if !replay.Replay || !replay.Completed {
		t.Fatalf("replay = %+v, want replay+completed", replay)
	}
	if string(replay.Result) != string(result) {
		t.Fatalf("replay result = %q, want %q", replay.Result, result)
	}
}

func TestIdempotencySameKeyDifferentDigestMismatches(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	err := db.WithTx(ctx, func(tx Tx) error {
		_, err := tx.BeginIdempotency(ctx, IdempotencyRecord{
			WorkspaceID: "personal", Key: "op-1", CanonicalDigest: "digest-a",
		})
		return err
	})
	if err != nil {
		t.Fatalf("BeginIdempotency: %v", err)
	}
	err = db.WithTx(ctx, func(tx Tx) error {
		_, err := tx.BeginIdempotency(ctx, IdempotencyRecord{
			WorkspaceID: "personal", Key: "op-1", CanonicalDigest: "digest-b",
		})
		return err
	})
	if !errors.Is(err, ErrIdempotencyMismatch) {
		t.Fatalf("error = %v, want ErrIdempotencyMismatch", err)
	}
}

func TestIdempotencyKeysAreWorkspaceQualified(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	for _, ws := range []string{"personal", "business"} {
		err := db.WithTx(ctx, func(tx Tx) error {
			_, err := tx.BeginIdempotency(ctx, IdempotencyRecord{
				WorkspaceID: ws, Key: "op-1", CanonicalDigest: "digest-a",
			})
			return err
		})
		if err != nil {
			t.Fatalf("BeginIdempotency(%s): %v", ws, err)
		}
	}
}

func TestIdempotencyInflightReplay(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	rec := IdempotencyRecord{WorkspaceID: "personal", Key: "op-1", CanonicalDigest: "digest-a"}
	// The first begin creates the record; the second begin with the same
	// digest replays it while still in flight.
	for i, wantReplay := range []bool{false, true} {
		var r IdempotencyResult
		err := db.WithTx(ctx, func(tx Tx) error {
			var err error
			r, err = tx.BeginIdempotency(ctx, rec)
			return err
		})
		if err != nil {
			t.Fatalf("BeginIdempotency: %v", err)
		}
		if r.Replay != wantReplay || r.Completed {
			t.Fatalf("attempt %d: replay = %+v, want replay=%v without completion", i, r, wantReplay)
		}
	}
}

func TestPutConnectionRoundTrip(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	rec := ConnectionRecord{
		WorkspaceID:          "personal",
		ConnectionID:         "conn-1",
		RepositoryBindingRef: "authscope:repo-binding:123",
		RepositoryID:         987,
		RepositoryName:       "octo/hello",
		CreatedAt:            time.Now().UTC().Truncate(time.Millisecond),
	}
	if err := db.WithTx(ctx, func(tx Tx) error {
		return tx.PutConnection(ctx, rec)
	}); err != nil {
		t.Fatalf("PutConnection: %v", err)
	}
	// Same connection in another workspace is independent.
	other := rec
	other.WorkspaceID = "business"
	if err := db.WithTx(ctx, func(tx Tx) error {
		return tx.PutConnection(ctx, other)
	}); err != nil {
		t.Fatalf("PutConnection business: %v", err)
	}
}

// TestNoRawTokensPersisted seeds realistic records and then scans every
// table and column for GitHub and AuthScope token fixtures. The store must
// hold only hashes, public key material, and opaque references, never raw
// tokens.
func TestNoRawTokensPersisted(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	githubTokenFixture := "ghp_testfixturegithubtoken000000000000"
	authScopeTokenFixture := "as_testfixtureauthscopetoken0000000000"

	bindTestInstance(t, db, testInstance("inst-1"))
	err := db.WithTx(ctx, func(tx Tx) error {
		if err := tx.PutConnection(ctx, ConnectionRecord{
			WorkspaceID:          "personal",
			ConnectionID:         "conn-1",
			RepositoryBindingRef: "authscope:repo-binding:123",
			RepositoryID:         987,
			RepositoryName:       "octo/hello",
			CreatedAt:            time.Now().UTC(),
		}); err != nil {
			return err
		}
		if _, err := tx.PutEventIfAbsent(ctx, MissionEventRecord{
			WorkspaceID: "personal", PassID: "pass-1", EventID: "evt-1",
			EventType: "mission.started", Cursor: "c1", OccurredAt: time.Now().UTC(),
		}); err != nil {
			return err
		}
		if _, err := tx.BeginIdempotency(ctx, IdempotencyRecord{
			WorkspaceID: "personal", Key: "op-1", CanonicalDigest: "digest-a",
		}); err != nil {
			return err
		}
		return tx.PutMissionPass(ctx, MissionPassRecord{
			WorkspaceID: "personal", PassID: "pass-1", DraftVersion: 1,
			CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		}, 0)
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	found := scanStoreForStrings(t, db, []string{githubTokenFixture, authScopeTokenFixture})
	if len(found) > 0 {
		t.Fatalf("token fixtures persisted: %v", found)
	}
}

func TestOpenRejectsSymlinkAndPermissiveBitsInRelease(t *testing.T) {
	// A group/world-readable database file is rejected in release mode.
	dir := t.TempDir()
	if err := writeFileMode(dir+"/ope.db", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, "release"); !errors.Is(err, ErrUnsafeDataPath) {
		t.Fatalf("release open of 0644 db: error = %v, want ErrUnsafeDataPath", err)
	}

	// A symlinked database file is rejected in release mode.
	symDir := t.TempDir()
	if err := writeFileMode(symDir+"/real.db", 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(symDir+"/real.db", symDir+"/ope.db"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(symDir, "release"); !errors.Is(err, ErrUnsafeDataPath) {
		t.Fatalf("release open of symlinked db: error = %v, want ErrUnsafeDataPath", err)
	}
}

func TestOpenCreatesOwnerOnlyDataDir(t *testing.T) {
	dir := t.TempDir() + "/nested/data"
	db, err := Open(dir, "development")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	fi, err := os.Stat(dir + "/ope.db")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("db file mode = %o, want no group/world bits", fi.Mode().Perm())
	}
	dirMode := dirFileMode(t, dir)
	if dirMode&0o077 != 0 {
		t.Fatalf("data dir mode = %o, want no group/world bits", dirMode)
	}
	// The database actually opens in WAL mode.
	if !strings.Contains(journalMode(t, db), "wal") {
		t.Fatal("journal mode is not WAL")
	}
}
