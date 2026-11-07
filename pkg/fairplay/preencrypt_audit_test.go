package fairplay

import (
	"encoding/binary"
	"testing"
)

// signedPreEncryptionAuditFixture uses synthetic page contents and separate
// ordinary and pre-encryption tables. Both tables cover the entire code limit.
func signedPreEncryptionAuditFixture(t *testing.T, cryptOff, cryptSize uint32, shift, hashType byte) ([]byte, machoLayout) {
	t.Helper()
	codeLimit := int(cryptOff + cryptSize)
	pageSize := 1 << shift
	if shift == 0 {
		pageSize = codeLimit
	}
	slots := (codeLimit + pageSize - 1) / pageSize
	hashSize := map[byte]int{1: 20, 2: 32, 3: 20, 4: 48}[hashType]
	dir := make([]byte, 96+2*slots*hashSize)
	put := func(off int, v uint32) { binary.BigEndian.PutUint32(dir[off:], v) }
	put(0, csMagicCodeDirectory)
	put(4, uint32(len(dir)))
	put(8, 0x20500)
	put(16, 96)
	put(28, uint32(slots))
	put(32, uint32(codeLimit))
	put(92, uint32(96+slots*hashSize))
	dir[36], dir[37], dir[39] = byte(hashSize), hashType, shift
	body := make([]byte, codeLimit)
	for i := range body {
		body[i] = byte(i % 251)
	}
	for slot := 0; slot < slots; slot++ {
		start, end := slot*pageSize, min((slot+1)*pageSize, codeLimit)
		hash, err := hashCodePage(hashType, body[start:end])
		if err != nil {
			t.Fatal(err)
		}
		copy(dir[96+slots*hashSize+slot*hashSize:], hash[:hashSize])
		ordinary := append([]byte(nil), body[start:end]...)
		ordinary[0] ^= 1
		hash, err = hashCodePage(hashType, ordinary)
		if err != nil {
			t.Fatal(err)
		}
		copy(dir[96+slot*hashSize:], hash[:hashSize])
	}
	sig := make([]byte, 20)
	binary.BigEndian.PutUint32(sig, csMagicEmbeddedSignature)
	binary.BigEndian.PutUint32(sig[4:], uint32(20+len(dir)))
	binary.BigEndian.PutUint32(sig[8:], 1)
	binary.BigEndian.PutUint32(sig[16:], 20)
	sig = append(sig, dir...)
	layout := machoLayout{cryptOffset: cryptOff, cryptSize: cryptSize, signatureOffset: uint32(codeLimit), signatureSize: uint32(len(sig))}
	return append(body, sig...), layout
}

func TestPreEncryptionCodeDirectoryCoverage(t *testing.T) {
	for _, tc := range []struct {
		name         string
		off, size    uint32
		shift        byte
		first, count int
	}{
		{"aligned", 4096, 8192, 12, 1, 2}, {"partial larger page", 4096, 8192, 13, 0, 2}, {"single larger page", 4096, 4096, 14, 0, 1}, {"unpaged", 4096, 8192, 0, 0, 1},
	} {
		for _, hashType := range []byte{1, 2, 3, 4} {
			t.Run(tc.name+string(rune('0'+hashType)), func(t *testing.T) {
				blob, layout := signedPreEncryptionAuditFixture(t, tc.off, tc.size, tc.shift, hashType)
				got, err := auditPreEncryptionCodeDirectories(blob, layout)
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != 1 || got[0].FirstSlot != tc.first || got[0].SlotCount != tc.count || got[0].MatchedSlots != tc.count {
					t.Fatalf("wrong coverage: %+v", got)
				}
				ordinary, err := auditCodeDirectories(blob, layout)
				if err != nil || ordinary[0].MatchedSlots != 0 {
					t.Fatal("pre-encryption audit did not use independent table")
				}
				// Even a zero plaintext byte at the end of the encrypted region is checked.
				index := int(layout.cryptOffset + layout.cryptSize - 1)
				blob[index] = 0
				// Rebuild the final expected hash for this zero before tampering it.
				page := 1 << tc.shift
				if tc.shift == 0 {
					page = index + 1
				}
				slot := index / page
				dir := blob[int(layout.signatureOffset)+20:]
				hashSize := int(dir[36])
				pre := int(binary.BigEndian.Uint32(dir[92:96]))
				hash, err := hashCodePage(hashType, blob[slot*page:min((slot+1)*page, int(layout.signatureOffset))])
				if err != nil {
					t.Fatal(err)
				}
				copy(dir[pre+slot*hashSize:], hash[:hashSize])
				blob[index] = 1
				got, err = auditPreEncryptionCodeDirectories(blob, layout)
				if err != nil || got[0].MatchedSlots != tc.count-1 {
					t.Fatal("last-page corruption was not detected")
				}
			})
		}
	}
}

func TestPreEncryptionCodeDirectoryRejectsInvalidTable(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]byte)
	}{
		{"inside header", func(d []byte) { binary.BigEndian.PutUint32(d[92:], 95) }},
		{"out of bounds", func(d []byte) { binary.BigEndian.PutUint32(d[92:], uint32(len(d)-1)) }},
		{"offset overflow", func(d []byte) { binary.BigEndian.PutUint32(d[92:], ^uint32(0)) }},
		{"extended header short", func(d []byte) { binary.BigEndian.PutUint32(d[8:], 0x20600); binary.BigEndian.PutUint32(d[4:], 100) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blob, layout := signedPreEncryptionAuditFixture(t, 4096, 4096, 12, 2)
			tc.change(blob[int(layout.signatureOffset)+20:])
			if _, err := auditPreEncryptionCodeDirectories(blob, layout); err == nil {
				t.Fatal("accepted invalid pre-encryption table")
			}
		})
	}
}

func TestPreEncryptionCodeDirectoryAbsent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]byte)
	}{
		{"old version", func(d []byte) { binary.BigEndian.PutUint32(d[8:], 0x20400) }},
		{"zero offset", func(d []byte) { binary.BigEndian.PutUint32(d[92:], 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blob, layout := signedPreEncryptionAuditFixture(t, 4096, 4096, 12, 2)
			dir := blob[int(layout.signatureOffset)+20:]
			tc.change(dir)
			got, err := auditPreEncryptionCodeDirectories(blob, layout)
			if err != nil || got == nil || len(got) != 0 {
				t.Fatalf("absent table: %+v, %v", got, err)
			}
			ordinary, err := auditCodeDirectories(blob, layout)
			if err != nil || len(ordinary) != 1 || ordinary[0].MatchedSlots != 0 {
				t.Fatalf("ordinary audit changed: %+v, %v", ordinary, err)
			}
			// Missing optional metadata does not excuse a malformed directory.
			dir[37] = 0xff
			if _, err := auditPreEncryptionCodeDirectories(blob, layout); err == nil {
				t.Fatal("accepted unsupported hash geometry in an absent-table directory")
			}
		})
	}
}

func TestCodeDirectoryVersionHeaderBounds(t *testing.T) {
	for _, tc := range []struct {
		version uint32
		size    int
	}{{0x20200, 52}, {0x20300, 64}, {0x20400, 88}, {0x20500, 96}, {0x20600, 108}} {
		t.Run(string(rune(tc.version>>8)), func(t *testing.T) {
			blob, layout := signedPreEncryptionAuditFixture(t, 4096, 4096, 12, 2)
			dir := blob[int(layout.signatureOffset)+20:]
			binary.BigEndian.PutUint32(dir[8:], tc.version)
			binary.BigEndian.PutUint32(dir[4:], uint32(tc.size-1))
			if _, err := auditCodeDirectories(blob, layout); err == nil {
				t.Fatal("accepted truncated versioned header")
			}
		})
	}
}

func TestPreEncryptionAuditsEveryDirectory(t *testing.T) {
	first, layout := signedPreEncryptionAuditFixture(t, 4096, 4096, 12, 2)
	second, _ := signedPreEncryptionAuditFixture(t, 4096, 4096, 12, 1)
	dirA := append([]byte(nil), first[int(layout.signatureOffset)+20:]...)
	dirB := append([]byte(nil), second[int(layout.signatureOffset)+20:]...)
	sig := make([]byte, 28)
	binary.BigEndian.PutUint32(sig, csMagicEmbeddedSignature)
	binary.BigEndian.PutUint32(sig[4:], uint32(len(sig)+len(dirA)+len(dirB)))
	binary.BigEndian.PutUint32(sig[8:], 2)
	binary.BigEndian.PutUint32(sig[16:], uint32(len(sig)))
	binary.BigEndian.PutUint32(sig[24:], uint32(len(sig)+len(dirA)))
	sig = append(sig, dirA...)
	sig = append(sig, dirB...)
	blob := append(append([]byte(nil), first[:layout.signatureOffset]...), sig...)
	layout.signatureSize = uint32(len(sig))
	got, err := auditPreEncryptionCodeDirectories(blob, layout)
	if err != nil || len(got) != 2 || got[0].MatchedSlots != 1 || got[1].MatchedSlots != 1 {
		t.Fatalf("incorrect multi-directory audit: %+v, %v", got, err)
	}
	// Unencrypted, non-intersecting slot changes are outside this audit.
	blob[0] ^= 1
	got, err = auditPreEncryptionCodeDirectories(blob, layout)
	if err != nil || got[0].MatchedSlots != 1 || got[1].MatchedSlots != 1 {
		t.Fatal("audited a non-intersecting slot")
	}
	// A missing second table is skipped; the first table remains authoritative.
	secondOffset := int(layout.signatureOffset) + 28 + len(dirA)
	binary.BigEndian.PutUint32(blob[secondOffset+92:], 0)
	got, err = auditPreEncryptionCodeDirectories(blob, layout)
	if err != nil || len(got) != 1 || got[0].MatchedSlots != 1 {
		t.Fatalf("partial table availability: %+v, %v", got, err)
	}
	blob[layout.cryptOffset] ^= 1
	got, err = auditPreEncryptionCodeDirectories(blob, layout)
	if err != nil || len(got) != 1 || got[0].SlotCount != 1 || got[0].MatchedSlots != 0 {
		t.Fatalf("available table mismatch was lost: %+v, %v", got, err)
	}
	firstOffset := int(layout.signatureOffset) + 28
	firstPreOffset := binary.BigEndian.Uint32(blob[firstOffset+92:])
	binary.BigEndian.PutUint32(blob[firstOffset+92:], 0)
	got, err = auditPreEncryptionCodeDirectories(blob, layout)
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("no tables across directories: %+v, %v", got, err)
	}
	binary.BigEndian.PutUint32(blob[firstOffset+92:], firstPreOffset)
	// A present but invalid second table remains an error, even when the first
	// table already produced a report.
	binary.BigEndian.PutUint32(blob[secondOffset+92:], uint32(len(dirB)-1))
	if _, err = auditPreEncryptionCodeDirectories(blob, layout); err == nil {
		t.Fatal("accepted malformed second table")
	}
}

func TestPreEncryptionAuditRejectsInvalidSignatureWithoutTables(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]byte)
	}{
		{"bad superblob", func(s []byte) { binary.BigEndian.PutUint32(s, 0) }},
		{"no code directory", func(s []byte) { binary.BigEndian.PutUint32(s[20:], 0) }},
		{"invalid item length", func(s []byte) { binary.BigEndian.PutUint32(s[24:], 7) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blob, layout := signedPreEncryptionAuditFixture(t, 4096, 4096, 12, 2)
			sig := blob[layout.signatureOffset:]
			binary.BigEndian.PutUint32(sig[20+92:], 0)
			tc.change(sig)
			if _, err := auditPreEncryptionCodeDirectories(blob, layout); err == nil {
				t.Fatal("accepted malformed or missing CodeDirectory")
			}
		})
	}
}
