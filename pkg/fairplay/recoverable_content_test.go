package fairplay

import (
	"archive/zip"
	"testing"
)

func TestUnencryptedRecoveryRangeRequiresMatchingCodeHashes(t *testing.T) {
	blob, layout := signedAuditFixture(t, 4096, 8192, 12, 2)
	if err := verifyUnencryptedRecoveryRange(blob, layout); err != nil {
		t.Fatal(err)
	}
	blob[layout.cryptOffset+layout.cryptSize-1] ^= 1
	if err := verifyUnencryptedRecoveryRange(blob, layout); err == nil {
		t.Fatal("accepted a modified range without a page table")
	}
	if err := verifyUnencryptedRecoveryRange(blob[:layout.signatureOffset], layout); err == nil {
		t.Fatal("accepted a missing signature")
	}
}

func TestRecoveryPageTablePresenceIncludesInvalidMembers(t *testing.T) {
	const route = "Payload/Test.app/SC_Info/Test.sinf"
	const base = "Payload/Test.app/SC_Info/Test"
	files := map[string]*zip.File{base + ".supx": {}}
	if hasRecoveryPageTable(files, route) {
		t.Fatal("unrelated auxiliary file treated as a page table")
	}
	for _, suffix := range []string{".supf", ".v5.supf", ".supp", ".v4.supp"} {
		if !hasRecoveryPageTable(map[string]*zip.File{base + suffix: nil}, route) {
			t.Fatalf("invalid %s member bypassed table validation", suffix)
		}
	}
}
