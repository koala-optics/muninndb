package keys

import "testing"

func TestPayloadReceiptKeyIncludesVaultScope(t *testing.T) {
	wsA := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	wsB := [8]byte{8, 7, 6, 5, 4, 3, 2, 1}
	keyA := PayloadReceiptKey(wsA, "same-op")
	keyB := PayloadReceiptKey(wsB, "same-op")

	if len(keyA) != 17 || len(keyB) != 17 {
		t.Fatalf("payload receipt keys must be 17 bytes: %d, %d", len(keyA), len(keyB))
	}
	if string(keyA) == string(keyB) {
		t.Fatal("same op_id in different vaults produced the same key")
	}
	if string(keyA[1:9]) != string(wsA[:]) || string(keyB[1:9]) != string(wsB[:]) {
		t.Fatal("payload receipt key does not contain the vault prefix")
	}
}
