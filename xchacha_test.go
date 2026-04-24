package xchacha_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"testing"

	xchacha "github.com/alvarolm/go-sqlite3-xchacha"
	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/driver"
)

// persistWAL asks SQLite to NOT delete the -wal file on clean shutdown.
// Needed for tests that want to inspect/tamper with the WAL after db.Close().
func persistWAL(conn *sqlite3.Conn) error {
	if err := xchacha.ReserveBytes(conn); err != nil {
		return err
	}
	_, err := conn.FileControl("main", sqlite3.FCNTL_PERSIST_WAL, true)
	return err
}

func openNewWALTest(t testing.TB, path, textkey string) *sql.DB {
	t.Helper()
	uri := "file:" + filepath.ToSlash(path) + "?vfs=xchacha"
	db, err := driver.Open(uri, persistWAL)
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

// Test_wal_before_textkey_fails pins the observable guarantee that any write
// issued before the key PRAGMA is refused, and that no encrypted sidecar file
// is left behind. This documents the current main-DB guard (ReadAt returns
// CANTOPEN while aead == nil) that indirectly protects the openAux branch
// where main.auxKey == nil. If either this test or the main-DB guard is ever
// relaxed, the openAux silent-random-key branch becomes reachable.
func Test_wal_before_textkey_fails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	uri := "file:" + filepath.ToSlash(path) + "?vfs=xchacha"
	ctx := context.Background()

	db, err := driver.Open(uri, xchacha.ReserveBytes)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	_, err1 := db.ExecContext(ctx, `PRAGMA journal_mode=WAL`)
	_, err2 := db.ExecContext(ctx, `CREATE TABLE t(x); INSERT INTO t VALUES(1)`)
	if err1 == nil && err2 == nil {
		t.Fatal("expected error when writing before PRAGMA textkey, got none")
	}

	// No aux file should have been produced under a random key.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "test.db" {
			t.Errorf("unexpected sidecar file %q — openAux may have been "+
				"reached while main.auxKey was nil", e.Name())
		}
	}
}

// Test_wal_roundtrip: enable WAL mode, insert rows, close, reopen, SELECT.
// Exercises the new AEAD aux-file format end-to-end.
func Test_wal_roundtrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	const key = "wal-roundtrip-key"
	ctx := context.Background()

	db := openNewWALTest(t, path, key)
	if _, err := db.ExecContext(ctx, `PRAGMA journal_mode=WAL`); err != nil {
		t.Fatalf("wal mode: %v", err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA wal_autocheckpoint=0`); err != nil {
		t.Fatalf("wal_autocheckpoint: %v", err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE t(x INTEGER, s TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	for i := 0; i < 100; i++ {
		if _, err := db.ExecContext(ctx, `INSERT INTO t VALUES(?, ?)`, i, "row-value-for-testing"); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	db.Close()

	// Verify a -wal file exists (data must not have been checkpointed and
	// persistWAL prevented deletion on close).
	if _, err := os.Stat(path + "-wal"); err != nil {
		t.Fatalf("expected -wal file to exist: %v", err)
	}

	db = openExistingEncrypted(t, path, key)
	defer db.Close()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM t`).Scan(&count); err != nil {
		t.Fatalf("select: %v", err)
	}
	if count != 100 {
		t.Errorf("count: got %d want 100", count)
	}
}

// Test_rollback_journal_roundtrip: default DELETE journal mode; a ROLLBACK
// must leave the table empty; a committed INSERT must round-trip.
func Test_rollback_journal_roundtrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	const key = "rollback-key"
	ctx := context.Background()

	db := openNewEncrypted(t, path, key)
	defer db.Close()
	if _, err := db.ExecContext(ctx, `CREATE TABLE t(x INTEGER)`); err != nil {
		t.Fatalf("create: %v", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO t VALUES(1),(2),(3)`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM t`).Scan(&count); err != nil {
		t.Fatalf("select after rollback: %v", err)
	}
	if count != 0 {
		t.Errorf("count after rollback: got %d want 0", count)
	}

	if _, err := db.ExecContext(ctx, `INSERT INTO t VALUES(42)`); err != nil {
		t.Fatalf("commit insert: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT x FROM t`).Scan(&count); err != nil {
		t.Fatalf("select after commit: %v", err)
	}
	if count != 42 {
		t.Errorf("committed row: got %d want 42", count)
	}
}

// walTamperAt creates a WAL-mode DB, writes rows, closes, flips a byte in the
// WAL file at physical offset `flipOffset`, reopens, and asserts SELECT fails.
func walTamperAt(t *testing.T, flipOffset int64, label string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	const key = "wal-tamper-key"
	ctx := context.Background()

	db := openNewWALTest(t, path, key)
	if _, err := db.ExecContext(ctx, `PRAGMA journal_mode=WAL`); err != nil {
		t.Fatalf("%s wal mode: %v", label, err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA wal_autocheckpoint=0`); err != nil {
		t.Fatalf("%s wal_autocheckpoint: %v", label, err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE t(x INTEGER); INSERT INTO t VALUES (1),(2),(3)`); err != nil {
		t.Fatalf("%s setup: %v", label, err)
	}
	db.Close()

	walPath := path + "-wal"
	raw, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatalf("%s read wal: %v", label, err)
	}
	if int64(len(raw)) <= flipOffset {
		t.Fatalf("%s wal too small (%d) for offset %d", label, len(raw), flipOffset)
	}
	raw[flipOffset] ^= 0xFF
	if err := os.WriteFile(walPath, raw, 0o600); err != nil {
		t.Fatalf("%s write wal: %v", label, err)
	}

	db2 := openExistingEncrypted(t, path, key)
	defer db2.Close()
	if _, err := db2.ExecContext(ctx, `SELECT * FROM t`); err == nil {
		t.Errorf("%s: expected tampered WAL read to fail, got nil", label)
	}
}

// Test_wal_tamper_ciphertext: flip a byte in the ciphertext region of WAL
// block 0 (offset 0..4095 within the 4136-byte physical block).
func Test_wal_tamper_ciphertext(t *testing.T) {
	t.Parallel()
	walTamperAt(t, 100, "ciphertext")
}

// Test_wal_tamper_nonce: flip a byte in the nonce region of WAL block 0
// (offset 4096..4119 within the physical block).
func Test_wal_tamper_nonce(t *testing.T) {
	t.Parallel()
	walTamperAt(t, 4100, "nonce")
}

// Test_wal_tamper_tag: flip a byte in the tag region of WAL block 0
// (offset 4120..4135 within the physical block).
func Test_wal_tamper_tag(t *testing.T) {
	t.Parallel()
	walTamperAt(t, 4125, "tag")
}

// Test_transient_temp_table: CREATE TEMP TABLE exercises the transient-DB
// path through openAux with no associated main DB.
func Test_transient_temp_table(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	const key = "transient-key"
	ctx := context.Background()

	db := openNewEncrypted(t, path, key)
	defer db.Close()
	if _, err := db.ExecContext(ctx, `CREATE TEMP TABLE tmp(x INTEGER); INSERT INTO tmp VALUES (7),(8),(9)`); err != nil {
		t.Fatalf("temp table: %v", err)
	}
	var sum int
	if err := db.QueryRowContext(ctx, `SELECT SUM(x) FROM tmp`).Scan(&sum); err != nil {
		t.Fatalf("select: %v", err)
	}
	if sum != 24 {
		t.Errorf("sum: got %d want 24", sum)
	}
}

// Test_aux_write_past_eof: a large transaction forces the rollback journal to
// grow past its current EOF, exercising the RMW-on-EOF path in auxFile.WriteAt.
func Test_aux_write_past_eof(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	const key = "eof-key"
	ctx := context.Background()

	db := openNewEncrypted(t, path, key)
	defer db.Close()
	if _, err := db.ExecContext(ctx, `CREATE TABLE t(x INTEGER, s BLOB)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	// One transaction, many large inserts — forces journal growth.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	blob := make([]byte, 2000)
	for i := range blob {
		blob[i] = byte(i)
	}
	for i := 0; i < 50; i++ {
		if _, err := tx.ExecContext(ctx, `INSERT INTO t VALUES(?, ?)`, i, blob); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM t`).Scan(&count); err != nil {
		t.Fatalf("select: %v", err)
	}
	if count != 50 {
		t.Errorf("count: got %d want 50", count)
	}
}

// Test_legacy_aux_format_rejected: a pre-existing WAL-looking file whose size
// is a multiple of 4096 (but not 4136) must be refused by the openAux probe.
func Test_legacy_aux_format_rejected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	const key = "legacy-key"
	ctx := context.Background()

	// Create a valid encrypted DB with some data so SQLite has something to open.
	db := openNewEncrypted(t, path, key)
	if _, err := db.ExecContext(ctx, `CREATE TABLE t(x INTEGER); INSERT INTO t VALUES (1),(2)`); err != nil {
		t.Fatalf("setup: %v", err)
	}
	db.Close()

	// Pre-plant a "legacy format" WAL file: random bytes, size 8192 (2 * 4096,
	// NOT a multiple of 4136). The openAux probe should reject it.
	legacy := make([]byte, 8192)
	for i := range legacy {
		legacy[i] = byte(i)
	}
	if err := os.WriteFile(path+"-wal", legacy, 0o600); err != nil {
		t.Fatalf("write legacy wal: %v", err)
	}

	// Reopen — SQLite will attempt to recover the -wal file on first access.
	uri := "file:" + filepath.ToSlash(path) + "?vfs=xchacha"
	db2, err := driver.Open(uri)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db2.Close()
	if _, err := db2.ExecContext(ctx, `PRAGMA textkey = '`+key+`'`); err != nil {
		// Acceptable: legacy probe may surface here.
		return
	}
	if _, err := db2.ExecContext(ctx, `SELECT * FROM t`); err == nil {
		t.Error("expected legacy-wal rejection, got nil error")
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

// Test_vacuum_roundtrip exercises the subjournal + temp-DB branches of
// openAux: VACUUM copies every page into a transient DB, swaps, then deletes.
// Padding the rows ensures VACUUM does real work before the final swap.
func Test_vacuum_roundtrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	const key = "vacuum-key"
	ctx := context.Background()

	db := openNewEncrypted(t, path, key)
	if _, err := db.ExecContext(ctx, `CREATE TABLE t(x INTEGER, s TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	for i := 0; i < 100; i++ {
		if _, err := db.ExecContext(ctx, `INSERT INTO t VALUES(?, ?)`, i,
			"padding-padding-padding-padding-padding"); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM t WHERE x % 2 = 0`); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := db.ExecContext(ctx, `VACUUM`); err != nil {
		t.Fatalf("vacuum: %v", err)
	}
	db.Close()

	db = openExistingEncrypted(t, path, key)
	defer db.Close()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM t`).Scan(&count); err != nil {
		t.Fatalf("select: %v", err)
	}
	if count != 50 {
		t.Errorf("count after vacuum: got %d want 50", count)
	}
}

// Test_attach_independent_keys validates that an ATTACH-ed main DB can carry
// its own key independent of the primary connection. For an *existing*
// encrypted file the key must be supplied in the ATTACH URI (textkey=...),
// not via PRAGMA: SQLite reads page 1 during ATTACH itself, so the empty-file
// EOF trick that works for the primary PRAGMA flow is not available here.
// Positive case only.
func Test_attach_independent_keys(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pathA := filepath.Join(dir, "a.db")
	pathB := filepath.Join(dir, "b.db")
	const keyA = "attach-key-a"
	const keyB = "attach-key-b"
	ctx := context.Background()

	dbA := openNewEncrypted(t, pathA, keyA)
	if _, err := dbA.ExecContext(ctx, `CREATE TABLE t(x); INSERT INTO t VALUES (1)`); err != nil {
		t.Fatalf("A setup: %v", err)
	}
	dbA.Close()

	dbB := openNewEncrypted(t, pathB, keyB)
	if _, err := dbB.ExecContext(ctx, `CREATE TABLE t(x); INSERT INTO t VALUES (2)`); err != nil {
		t.Fatalf("B setup: %v", err)
	}
	dbB.Close()

	db := openExistingEncrypted(t, pathA, keyA)
	defer db.Close()
	attachURI := "file:" + filepath.ToSlash(pathB) + "?vfs=xchacha&textkey=" + keyB
	if _, err := db.ExecContext(ctx, `ATTACH DATABASE '`+attachURI+`' AS b`); err != nil {
		t.Fatalf("attach: %v", err)
	}

	var xa, xb int
	if err := db.QueryRowContext(ctx, `SELECT x FROM main.t`).Scan(&xa); err != nil {
		t.Fatalf("select main: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT x FROM b.t`).Scan(&xb); err != nil {
		t.Fatalf("select b: %v", err)
	}
	if xa != 1 || xb != 2 {
		t.Errorf("attach rows: got (%d, %d) want (1, 2)", xa, xb)
	}
}

// Test_concurrent_pool_connections pins the supported pattern for
// database/sql connection pools: install reserve_bytes + key via a
// per-connection init hook through driver.Open, NOT via URI parameters.
//
// Background: URI-based key delivery (?hexkey=...) does reach every pool
// connection, but if reserve_bytes isn't also set per-connection, SQLite
// writes page 1 with header byte 20 == 0 and every subsequent pool open
// reads the header in setKey and fails with NOTADB. The init-hook pattern
// sets both per connection and is the only correct usage with a pool.
func Test_concurrent_pool_connections(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	const hexkey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	ctx := context.Background()

	init := func(conn *sqlite3.Conn) error {
		if err := xchacha.ReserveBytes(conn); err != nil {
			return err
		}
		return conn.Exec(`PRAGMA hexkey = '` + hexkey + `'`)
	}

	dsn := "file:" + filepath.ToSlash(path) + "?vfs=xchacha"
	db, err := driver.Open(dsn, init)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(4)

	if _, err := db.ExecContext(ctx, `CREATE TABLE t(x INTEGER); INSERT INTO t VALUES (1),(2),(3)`); err != nil {
		t.Fatalf("setup: %v", err)
	}

	const workers = 16
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var c int
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM t`).Scan(&c); err != nil {
				errs <- err
				return
			}
			if c != 3 {
				errs <- &countMismatch{got: c, want: 3}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("worker: %v", err)
	}
}

type countMismatch struct{ got, want int }

func (c *countMismatch) Error() string {
	return "count mismatch"
}
