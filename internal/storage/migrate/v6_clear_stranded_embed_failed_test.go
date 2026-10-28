package migrate

import (
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

func setDigestFlags(t *testing.T, db *pebble.DB, id [16]byte, flags uint8) {
	t.Helper()
	if err := db.Set(keys.DigestFlagsKey(id), []byte{flags}, pebble.Sync); err != nil {
		t.Fatalf("set digest flags: %v", err)
	}
}

func getDigestFlags(t *testing.T, db *pebble.DB, id [16]byte) uint8 {
	t.Helper()
	val, closer, err := db.Get(keys.DigestFlagsKey(id))
	if err != nil {
		t.Fatalf("get digest flags: %v", err)
	}
	defer closer.Close()
	return val[0]
}

func TestClearStrandedEmbedFailed_ClearsOnlyUnembeddedFailures(t *testing.T) {
	db := openTestDB(t)
	stranded := [16]byte{1} // embed-failed, never embedded -> cleared, other bits kept
	embedded := [16]byte{2} // embedded + 0x80 (enrich-failed) -> untouched
	pending := [16]byte{3}  // ordinary pending row -> untouched
	setDigestFlags(t, db, stranded, 0x80|0x01)
	setDigestFlags(t, db, embedded, 0x80|0x02)
	setDigestFlags(t, db, pending, 0x01)

	for run := 0; run < 2; run++ { // second run proves idempotence
		if err := ClearStrandedEmbedFailed(db); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		if got := getDigestFlags(t, db, stranded); got != 0x01 {
			t.Errorf("run %d: stranded flags = %#x, want 0x01", run, got)
		}
		if got := getDigestFlags(t, db, embedded); got != 0x82 {
			t.Errorf("run %d: embedded flags = %#x, want 0x82", run, got)
		}
		if got := getDigestFlags(t, db, pending); got != 0x01 {
			t.Errorf("run %d: pending flags = %#x, want 0x01", run, got)
		}
	}
}
