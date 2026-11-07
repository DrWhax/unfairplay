package fairplay

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIPAInventoryDuplicateDirectoryMarkers(t *testing.T) {
	type zipMember struct{ name, body string }
	for _, test := range []struct {
		name, want string
		members    []zipMember
	}{
		{
			name: "empty directory markers are harmless",
			want: "contains no supported encrypted Mach-O images",
			members: []zipMember{
				{"Payload/App.app/", ""}, {"Payload/App.app/", ""},
			},
		},
		{
			name: "duplicate regular files remain rejected",
			want: `duplicate IPA member "Payload/App.app/data"`,
			members: []zipMember{
				{"Payload/App.app/data", "one"}, {"Payload/App.app/data", "two"},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "App.ipa")
			output, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			archive := zip.NewWriter(output)
			for _, member := range test.members {
				writer, err := archive.Create(member.name)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := writer.Write([]byte(member.body)); err != nil {
					t.Fatal(err)
				}
			}
			if err := archive.Close(); err != nil {
				t.Fatal(err)
			}
			if err := output.Close(); err != nil {
				t.Fatal(err)
			}
			_, opened, err := openIPAInventory(path)
			if opened != nil {
				opened.Close()
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("inventory error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDecryptARMv6Thumb1RejectsWrongPageKey(t *testing.T) {
	blob, layout := signedPreEncryptionAuditFixture(t, pageBytes, pageBytes, 12, 2)
	layout.cpuType = cpuTypeARM
	layout.cpuSubtype = 6
	layout.cryptID = 1
	layout.cryptIDOffset = 16
	layout.instructionRanges = []machoFileRange{{
		offset: pageBytes, size: pageBytes, segment: "__TEXT", section: "__text",
		flags: sectionAttrPureInstructions | sectionAttrSomeInstructions,
	}}
	binary.LittleEndian.PutUint32(blob[layout.cryptIDOffset:], 1)

	var logical [16]byte
	for index := range logical {
		logical[index] = byte(index + 1)
	}
	var record [32]byte
	for index := range record {
		record[index] = byte(0x40 + index)
	}
	plaintext := make([]byte, pageBytes)
	for offset := 0; offset < len(plaintext); offset += 4 {
		binary.LittleEndian.PutUint16(plaintext[offset:offset+2], 0x2000)   // movs r0, #0
		binary.LittleEndian.PutUint16(plaintext[offset+2:offset+4], 0x4770) // bx lr
	}
	mask := appMaskFromLogicalKey(logical)
	deriver := newPageKeyDeriver(mask)
	key := deriver.pageKey(record[:16], pageBytes)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	copy(blob[pageBytes:2*pageBytes], plaintext)
	setSyntheticPreEncryptionHashes(t, blob, layout)
	cipher.NewCBCEncrypter(block, record[16:]).CryptBlocks(blob[pageBytes:2*pageBytes], plaintext)
	clear(key[:])

	directory := blob[int(layout.signatureOffset)+20:]
	for slot := 0; slot < int(layout.signatureOffset)/pageBytes; slot++ {
		hash, err := hashCodePage(2, blob[slot*pageBytes:(slot+1)*pageBytes])
		if err != nil {
			t.Fatal(err)
		}
		copy(directory[96+slot*32:], hash)
	}
	encrypted := append([]byte(nil), blob...)
	image := encryptedImage{member: "Payload/Test.app/Test", layout: layout, sliceSize: uint64(len(blob))}
	report, err := decryptImage(blob, image, [][32]byte{record}, mask, deriver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blob[pageBytes:2*pageBytes], plaintext) || report.Architecture != "armv6" ||
		report.PlaintextValidation != "code-directory-pre-encryption-hashes" || len(report.PreEncryptionCodeDirectories) != 1 {
		t.Fatalf("unexpected ARMv6 result: %+v", report)
	}

	wrongLogical := logical
	wrongLogical[0] ^= 0xff
	wrongMask := appMaskFromLogicalKey(wrongLogical)
	wrongDeriver := newPageKeyDeriver(wrongMask)
	binary.LittleEndian.PutUint32(encrypted[layout.cryptIDOffset:], 1)
	if _, err := decryptImage(encrypted, image, [][32]byte{record}, wrongMask, wrongDeriver); err == nil ||
		!strings.Contains(err.Error(), "plaintext page hash mismatch") {
		t.Fatalf("wrong ARMv6 page key returned %v", err)
	}
}

func TestDecryptMixedPageUsesPreEncryptionHash(t *testing.T) {
	blob, layout := signedPreEncryptionAuditFixture(t, pageBytes, pageBytes, 12, 2)
	layout.cpuType = cpuTypeARM64
	layout.cryptID = 1
	layout.cryptIDOffset = 16
	layout.instructionRanges = []machoFileRange{{
		offset: pageBytes, size: 598 * 4, segment: "__TEXT", section: "__mixed",
		flags: sectionAttrSomeInstructions,
	}}
	binary.LittleEndian.PutUint32(blob[layout.cryptIDOffset:], 1)

	var logical [16]byte
	for index := range logical {
		logical[index] = byte(index + 1)
	}
	var record [32]byte
	for index := range record {
		record[index] = byte(0x40 + index)
	}
	plaintext := bytes.Repeat([]byte{0xff}, pageBytes)
	for offset := 0; offset < 409*4; offset += 4 {
		binary.LittleEndian.PutUint32(plaintext[offset:offset+4], 0xd503201f)
	}
	mask := appMaskFromLogicalKey(logical)
	deriver := newPageKeyDeriver(mask)
	key := deriver.pageKey(record[:16], pageBytes)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	copy(blob[pageBytes:2*pageBytes], plaintext)
	setSyntheticPreEncryptionHashes(t, blob, layout)
	cipher.NewCBCEncrypter(block, record[16:]).CryptBlocks(blob[pageBytes:2*pageBytes], plaintext)
	clear(key[:])

	directory := blob[int(layout.signatureOffset)+20:]
	for slot := 0; slot < int(layout.signatureOffset)/pageBytes; slot++ {
		hash, err := hashCodePage(2, blob[slot*pageBytes:(slot+1)*pageBytes])
		if err != nil {
			t.Fatal(err)
		}
		copy(directory[96+slot*32:], hash)
	}

	image := encryptedImage{member: "Payload/Test.app/Test", layout: layout, sliceSize: uint64(len(blob))}
	missingTable := append([]byte(nil), blob...)
	binary.BigEndian.PutUint32(missingTable[int(layout.signatureOffset)+20+92:], 0)
	noHashWrongKey := append([]byte(nil), missingTable...)
	unverified, err := decryptImage(missingTable, image, [][32]byte{record}, mask, deriver)
	if err != nil || unverified.PlaintextValidation != "unavailable-no-pre-encryption-hashes" || len(unverified.PreEncryptionCodeDirectories) != 0 || !bytes.Equal(missingTable[pageBytes:2*pageBytes], plaintext) {
		t.Fatalf("missing table result: report=%+v err=%v", unverified, err)
	}
	wrongLogical := logical
	wrongLogical[0] ^= 0xff
	wrongMask := appMaskFromLogicalKey(wrongLogical)
	unverified, err = decryptImage(noHashWrongKey, image, [][32]byte{record}, wrongMask, newPageKeyDeriver(wrongMask))
	if err != nil || unverified.PlaintextValidation != "unavailable-no-pre-encryption-hashes" || len(unverified.PreEncryptionCodeDirectories) != 0 || bytes.Equal(noHashWrongKey[pageBytes:2*pageBytes], plaintext) {
		t.Fatalf("unverified wrong-key result: report=%+v err=%v", unverified, err)
	}
	malformedTable := append([]byte(nil), blob...)
	binary.BigEndian.PutUint32(malformedTable[int(layout.signatureOffset)+20+92:], ^uint32(0))
	if _, err := decryptImage(malformedTable, image, [][32]byte{record}, mask, deriver); err == nil || !strings.Contains(err.Error(), "pre-encryption table") {
		t.Fatalf("malformed pre-encryption hash table returned %v", err)
	}
	report, err := decryptImage(blob, image, [][32]byte{record}, mask, deriver)
	if err != nil || !bytes.Equal(blob[pageBytes:2*pageBytes], plaintext) || report.PlaintextValidation != "code-directory-pre-encryption-hashes" {
		t.Fatalf("mixed plaintext page rejected: %v", err)
	}
}

func TestDecryptUniversalSliceUsesEachPageOffset(t *testing.T) {
	blob, layout := signedPreEncryptionAuditFixture(t, pageBytes, 2*pageBytes, 12, 2)
	layout.cpuType = cpuTypeARM64
	layout.cryptID = 1
	layout.cryptIDOffset = 16
	layout.instructionRanges = []machoFileRange{{offset: uint64(layout.cryptOffset), size: uint64(layout.cryptSize)}}
	binary.LittleEndian.PutUint32(blob[layout.cryptIDOffset:], 1)

	image := encryptedImage{
		member: "Payload/Test.app/Test", supfMember: "Payload/Test.app/SC_Info/Test.v5.supf",
		sliceOffset: 0x4000, sliceSize: uint64(len(blob)), layout: layout,
	}
	var logical [16]byte
	for index := range logical {
		logical[index] = byte(index + 1)
	}
	records := make([][32]byte, 2)
	for page := range records {
		for index := range records[page] {
			records[page][index] = byte(0x40 + page*len(records[page]) + index)
		}
	}
	mask := appMaskFromLogicalKey(logical)
	deriver := newPageKeyDeriver(mask)
	plaintext := make([]byte, 2*pageBytes)
	copy(blob[pageBytes:3*pageBytes], plaintext)
	setSyntheticPreEncryptionHashes(t, blob, layout)
	for page := range records {
		key := deriver.pageKey(
			records[page][:16],
			image.sliceOffset+uint64(layout.cryptOffset)+uint64(page*pageBytes),
		)
		block, err := aes.NewCipher(key[:])
		if err != nil {
			t.Fatal(err)
		}
		start := int(layout.cryptOffset) + page*pageBytes
		cipher.NewCBCEncrypter(block, records[page][16:]).CryptBlocks(
			blob[start:start+pageBytes], plaintext[page*pageBytes:(page+1)*pageBytes],
		)
	}

	directory := blob[int(layout.signatureOffset)+20:]
	hashOffset, hashSize := 96, 32
	for slot := 0; slot < int(layout.signatureOffset)/pageBytes; slot++ {
		hash, err := hashCodePage(2, blob[slot*pageBytes:(slot+1)*pageBytes])
		if err != nil {
			t.Fatal(err)
		}
		copy(directory[hashOffset+slot*hashSize:], hash)
	}

	encryptedHash := digest(blob)
	encrypted := append([]byte(nil), blob...)
	report, err := decryptImage(blob, image, records, mask, deriver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blob[pageBytes:3*pageBytes], plaintext) {
		t.Fatal("universal slice did not decrypt with each encrypted page offset")
	}
	if report.EncryptedSHA256 != encryptedHash || report.DecryptedSHA256 != digest(blob) {
		t.Fatalf("unexpected image hashes: %+v", report)
	}
	if report.Architecture != "arm64" || report.PlaintextValidation != "code-directory-pre-encryption-hashes" || len(report.PreEncryptionCodeDirectories) != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	badRecords := append([][32]byte(nil), records...)
	badRecords[1][0] ^= 0xff
	if _, err := decryptImage(encrypted, image, badRecords, mask, deriver); err == nil || !strings.Contains(err.Error(), "plaintext page hash mismatch") {
		t.Fatalf("wrong final page key returned %v", err)
	}
}

// setSyntheticPreEncryptionHashes records the expected plaintext before encryption.
func setSyntheticPreEncryptionHashes(t *testing.T, blob []byte, layout machoLayout) {
	t.Helper()
	directory := blob[int(layout.signatureOffset)+20:]
	slots := int(layout.signatureOffset) / pageBytes
	for slot := 0; slot < slots; slot++ {
		hash, err := hashCodePage(2, blob[slot*pageBytes:(slot+1)*pageBytes])
		if err != nil {
			t.Fatal(err)
		}
		copy(directory[96+slots*32+slot*32:], hash)
	}
}
