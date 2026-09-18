// Shared test helpers for the store package. Tests never touch the real
// data directory; every test opens its own throwaway store.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func openTestStore(t *testing.T) Store {
	t.Helper()
	db, err := Open(t.TempDir(), "development")
	if err != nil {
		t.Fatalf("Open test store: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("Close test store: %v", err)
		}
	})
	return db
}

func testInstance(id string) InstanceRecord {
	return InstanceRecord{
		InstanceID:        id,
		WorkspaceID:       "ws-test",
		Hostname:          "ope.example.com",
		Origin:            "https://ope.example.com",
		RPID:              "ope.example.com",
		SessionCookieName: DeriveSessionCookieName(id),
		CreatedAt:         time.Now().UTC().Truncate(time.Millisecond),
	}
}

func bindTestInstance(t *testing.T, db Store, rec InstanceRecord) {
	t.Helper()
	ctx := context.Background()
	if err := db.WithTx(ctx, func(tx Tx) error {
		return tx.BindInstance(ctx, rec)
	}); err != nil {
		t.Fatalf("BindInstance: %v", err)
	}
}

func savePass(t *testing.T, db Store, workspace, passID string, draftVersion int64) {
	t.Helper()
	ctx := context.Background()
	err := db.WithTx(ctx, func(tx Tx) error {
		return tx.PutMissionPass(ctx, MissionPassRecord{
			WorkspaceID:  workspace,
			PassID:       passID,
			DraftVersion: draftVersion,
			CreatedAt:    time.Now().UTC(),
			UpdatedAt:    time.Now().UTC(),
		}, 0)
	})
	if err != nil {
		t.Fatalf("PutMissionPass: %v", err)
	}
}

// testSQLDB reaches the underlying *sql.DB of a test store. Tests and the
// store implementation live in the same package.
func testSQLDB(t *testing.T, db Store) *sql.DB {
	t.Helper()
	s, ok := db.(*sqliteStore)
	if !ok {
		t.Fatalf("test store has unexpected type %T", db)
	}
	return s.db
}

func writeFileMode(path string, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write([]byte("placeholder")); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func dirFileMode(t *testing.T, dir string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	return fi.Mode().Perm()
}

func journalMode(t *testing.T, db Store) string {
	t.Helper()
	var mode string
	if err := testSQLDB(t, db).QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	return mode
}

// scanStoreForStrings walks every user table and column and reports where
// any of the needles appears. It guards the invariant that raw provider
// tokens are never persisted.
func scanStoreForStrings(t *testing.T, db Store, needles []string) []string {
	t.Helper()
	sqldb := testSQLDB(t, db)
	rows, err := sqldb.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name <> 'schema_migrations'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			t.Fatalf("scan table name: %v", err)
		}
		tables = append(tables, name)
	}
	rows.Close()

	var hits []string
	for _, table := range tables {
		cols, err := tableColumns(sqldb, table)
		if err != nil {
			t.Fatalf("columns of %s: %v", table, err)
		}
		data, err := sqldb.Query(fmt.Sprintf("SELECT * FROM %q", table))
		if err != nil {
			t.Fatalf("select from %s: %v", table, err)
		}
		for data.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := data.Scan(ptrs...); err != nil {
				data.Close()
				t.Fatalf("scan %s: %v", table, err)
			}
			for i, v := range vals {
				s := fmt.Sprintf("%v", v)
				for _, needle := range needles {
					if needle != "" && strings.Contains(s, needle) {
						hits = append(hits, table+"."+cols[i])
					}
				}
			}
		}
		data.Close()
	}
	return hits
}

func tableColumns(sqldb *sql.DB, table string) ([]string, error) {
	rows, err := sqldb.Query(fmt.Sprintf("PRAGMA table_info(%q)", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dflt any
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols = append(cols, name)
	}
	return cols, rows.Err()
}
