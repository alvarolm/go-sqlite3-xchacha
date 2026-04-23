package xchacha_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	xchacha "github.com/alvarolm/go-sqlite3-xchacha"
	"github.com/ncruces/go-sqlite3/driver"
)

// openNewEncrypted creates a fresh encrypted DB at path with the given textkey.
// Uses xchacha.ReserveBytes as the driver init hook (that is how reserve_bytes
// is set on ncruces' driver — there is no SQL pragma for it).
func openNewEncrypted(t testing.TB, path, textkey string) *sql.DB {
	t.Helper()
	uri := "file:" + filepath.ToSlash(path) + "?vfs=xchacha"
	db, err := driver.Open(uri, xchacha.ReserveBytes)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `PRAGMA textkey = '`+textkey+`'`); err != nil {
		db.Close()
		t.Fatalf("textkey: %v", err)
	}
	return db
}

func openExistingEncrypted(t testing.TB, path, textkey string) *sql.DB {
	t.Helper()
	uri := "file:" + filepath.ToSlash(path) + "?vfs=xchacha"
	db, err := driver.Open(uri)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `PRAGMA textkey = '`+textkey+`'`); err != nil {
		db.Close()
		t.Fatalf("textkey: %v", err)
	}
	return db
}

// Test_roundtrip: create a DB, write rows, close, reopen with correct key, read rows back.
func Test_roundtrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	const key = "correct+horse+battery+staple"
	ctx := context.Background()

	db := openNewEncrypted(t, path, key)
	if _, err := db.ExecContext(ctx, `CREATE TABLE t(x INTEGER, s TEXT); INSERT INTO t VALUES (1, 'hello'), (2, 'world'), (3, 'xchacha')`); err != nil {
		t.Fatalf("create/insert: %v", err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA user_version = 0xBADDB`); err != nil {
		t.Fatalf("user_version: %v", err)
	}
	db.Close()

	db = openExistingEncrypted(t, path, key)
	defer db.Close()

	rows, err := db.QueryContext(ctx, `SELECT x, s FROM t ORDER BY x`)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	got := []string{}
	for rows.Next() {
		var x int
		var s string
		if err := rows.Scan(&x, &s); err != nil {
			t.Fatal(err)
		}
		got = append(got, s)
	}
	rows.Close()

	if len(got) != 3 || got[0] != "hello" || got[1] != "world" || got[2] != "xchacha" {
		t.Errorf("unexpected rows: %v", got)
	}

	var uv uint32
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&uv); err != nil {
		t.Fatal(err)
	}
	if uv != 0xBADDB {
		t.Errorf("user_version: got %x want 0xBADDB", uv)
	}
}

// Test_wrong_key: reopening with a different key must fail.
func Test_wrong_key(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	ctx := context.Background()

	db := openNewEncrypted(t, path, "right-key")
	if _, err := db.ExecContext(ctx, `CREATE TABLE t(x); INSERT INTO t VALUES (42)`); err != nil {
		t.Fatalf("setup: %v", err)
	}
	db.Close()

	uri := "file:" + filepath.ToSlash(path) + "?vfs=xchacha"
	db2, err := driver.Open(uri)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db2.Close()

	if _, err := db2.ExecContext(ctx, `PRAGMA textkey = 'wrong-key'`); err != nil {
		// Pragma itself may error on a wrong key. Acceptable.
		return
	}

	if _, err := db2.ExecContext(ctx, `SELECT * FROM t`); err == nil {
		t.Error("expected read with wrong key to fail, got nil")
	}
}

// Test_tamper: flipping a byte in the ciphertext region of page 1 must cause a
// detectable error on reopen. This is the capability adiantum/xts cannot offer.
func Test_tamper(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	const key = "tamper-key"
	ctx := context.Background()

	db := openNewEncrypted(t, path, key)
	if _, err := db.ExecContext(ctx, `CREATE TABLE t(x INTEGER); INSERT INTO t VALUES (1),(2),(3)`); err != nil {
		t.Fatalf("setup: %v", err)
	}
	db.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(raw) < 500 {
		t.Fatalf("file too small: %d", len(raw))
	}
	// Flip a single byte inside page 1's ciphertext region (past the 100-byte header).
	raw[500] ^= 0xFF
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	db2 := openExistingEncrypted(t, path, key)
	defer db2.Close()

	if _, err := db2.ExecContext(ctx, `SELECT * FROM t`); err == nil {
		t.Error("expected read of tampered DB to fail, got nil")
	}
}
