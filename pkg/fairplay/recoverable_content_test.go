package fairplay

import (
	"archive/zip"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRestoreFiltersAppleDoubleBeforePageTableVerification(t *testing.T) {
	const sidecar = "__MACOSX/Payload/Test.app/SC_Info/._Test.supf"
	const pageTable = "Payload/Test.app/SC_Info/Test.supf"
	for _, tc := range []struct {
		name, member, wantError string
		appleDouble             bool
	}{
		{"AppleDouble", sidecar, "no encrypted ranges to restore", true},
		{"invalid sidecar", sidecar, "SUPF envelope version", false},
		{"real route", pageTable, "SUPF envelope version", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "input.ipa")
			file, err := os.Create(input)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			w := zip.NewWriter(file)
			member, err := w.Create(tc.member)
			if err != nil {
				t.Fatal(err)
			}
			data := make([]byte, 26)
			if tc.appleDouble {
				binary.BigEndian.PutUint32(data[:4], 0x00051607)
				binary.BigEndian.PutUint32(data[4:8], 0x00020000)
			}
			if _, err := member.Write(data); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			err = RestoreRecoverableContent(input, filepath.Join(dir, "restored.ipa"), make([]byte, 16), nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("want %q, got %v", tc.wantError, err)
			}
		})
	}
}

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
