package migrate

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/prefix"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

func setVaultCount(t *testing.T, db *pebble.DB, vault [8]byte, count uint64) {
	t.Helper()
	var value [8]byte
	binary.BigEndian.PutUint64(value[:], count)
	if err := db.Set(keys.VaultCountKey(vault), value[:], pebble.Sync); err != nil {
		t.Fatalf("set vault count: %v", err)
	}
}

func getVaultCount(t *testing.T, db *pebble.DB, vault [8]byte) uint64 {
	t.Helper()
	value, closer, err := db.Get(keys.VaultCountKey(vault))
	if err != nil {
		t.Fatalf("get vault count: %v", err)
	}
	defer closer.Close()
	if len(value) != 8 {
		t.Fatalf("vault count length = %d, want 8", len(value))
	}
	return binary.BigEndian.Uint64(value)
}

func TestRebuildVaultCounts_RepairsInflatedCountsAndIsolatesVaults(t *testing.T) {
	db := openTestDB(t)
	first := [8]byte{1}
	second := [8]byte{2}
	writeMigrationEngram(t, db, first, [16]byte{1}, "first")
	writeMigrationEngram(t, db, first, [16]byte{2}, "second")
	writeMigrationEngram(t, db, second, [16]byte{3}, "third")
	setVaultCount(t, db, first, 52)
	setVaultCount(t, db, second, 2)

	if err := RebuildVaultCounts(db); err != nil {
		t.Fatalf("RebuildVaultCounts: %v", err)
	}
	if got := getVaultCount(t, db, first); got != 2 {
		t.Fatalf("first count = %d, want 2", got)
	}
	if got := getVaultCount(t, db, second); got != 1 {
		t.Fatalf("second count = %d, want 1", got)
	}
}

func TestRebuildVaultCounts_ZerosPersistedEmptyVaultAndIsIdempotent(t *testing.T) {
	db := openTestDB(t)
	empty := [8]byte{9}
	setVaultCount(t, db, empty, 51)

	if err := RebuildVaultCounts(db); err != nil {
		t.Fatalf("first rebuild: %v", err)
	}
	if got := getVaultCount(t, db, empty); got != 0 {
		t.Fatalf("empty count = %d, want 0", got)
	}
	if err := RebuildVaultCounts(db); err != nil {
		t.Fatalf("second rebuild: %v", err)
	}
	if got := getVaultCount(t, db, empty); got != 0 {
		t.Fatalf("empty count after second rebuild = %d, want 0", got)
	}
}

func TestRebuildVaultCounts_RejectsMalformedEngramKey(t *testing.T) {
	db := openTestDB(t)
	if err := db.Set([]byte{prefix.Engram, 1}, []byte("bad"), pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if err := RebuildVaultCounts(db); err == nil || !strings.Contains(err.Error(), "malformed engram key") {
		t.Fatalf("error = %v, want malformed engram key", err)
	}
}

func TestRebuildVaultCounts_RejectsMalformedCountKey(t *testing.T) {
	db := openTestDB(t)
	if err := db.Set([]byte{prefix.VaultCount, 1}, []byte("bad"), pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if err := RebuildVaultCounts(db); err == nil || !strings.Contains(err.Error(), "malformed count key") {
		t.Fatalf("error = %v, want malformed count key", err)
	}
}

func TestRegisterMigrations_IncludesVaultCountRepairAndDowngradeBoundary(t *testing.T) {
	if got := MaxRegisteredVersion(); got != 5 {
		t.Fatalf("MaxRegisteredVersion = %d, want 5", got)
	}

	db := openTestDB(t)
	if err := writeMigrationVersion(db, 5); err != nil {
		t.Fatal(err)
	}
	older := NewRunner(db)
	older.Register(Migration{Version: 4, Description: "older", Up: func(*pebble.DB) error { return nil }})
	if _, err := older.Run(); err == nil || !strings.Contains(err.Error(), "downgrade not supported") {
		t.Fatalf("error = %v, want downgrade refusal", err)
	}
}
