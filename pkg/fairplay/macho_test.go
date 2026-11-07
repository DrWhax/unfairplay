package fairplay

import (
	"archive/zip"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// signedAuditFixture contains ordinary test bytes and a self-consistent hash
// table. It needs no proprietary image, private state, or decryption key.
func signedAuditFixture(t *testing.T, cryptOffset, cryptSize uint32, shift, hashType byte) ([]byte, machoLayout) {
	t.Helper()
	codeLimit := int(cryptOffset + cryptSize)
	pageSize := 1 << shift
	if shift == 0 {
		pageSize = codeLimit
	}
	slots := (codeLimit + pageSize - 1) / pageSize
	hashSize := map[byte]int{1: 20, 2: 32, 3: 20, 4: 48}[hashType]
	directory := make([]byte, 44+slots*hashSize)
	put := func(offset int, value uint32) { binary.BigEndian.PutUint32(directory[offset:], value) }
	put(0, csMagicCodeDirectory)
	put(4, uint32(len(directory)))
	put(8, 0x20000)
	put(16, 44)
	put(28, uint32(slots))
	put(32, uint32(codeLimit))
	directory[36], directory[37], directory[39] = byte(hashSize), hashType, shift
	blob := make([]byte, codeLimit)
	for index := range blob {
		blob[index] = byte(index % 251)
	}
	for slot := range slots {
		start := slot * pageSize
		hash, err := hashCodePage(hashType, blob[start:min(start+pageSize, codeLimit)])
		if err != nil {
			t.Fatal(err)
		}
		copy(directory[44+slot*hashSize:], hash[:hashSize])
	}
	signature := make([]byte, 20)
	binary.BigEndian.PutUint32(signature, csMagicEmbeddedSignature)
	binary.BigEndian.PutUint32(signature[4:], uint32(20+len(directory)))
	binary.BigEndian.PutUint32(signature[8:], 1)
	binary.BigEndian.PutUint32(signature[16:], 20)
	signature = append(signature, directory...)
	layout := machoLayout{cryptOffset: cryptOffset, cryptSize: cryptSize, signatureOffset: uint32(codeLimit), signatureSize: uint32(len(signature))}
	return append(blob, signature...), layout
}

func TestCodeDirectoryCoversEveryIntersectingPage(t *testing.T) {
	for _, test := range []struct {
		name           string
		offset, size   uint32
		shift          byte
		first, checked int
	}{
		{"aligned", 4096, 8192, 12, 1, 2},
		{"partial final signature page", 4096, 8192, 13, 0, 2},
		{"signature page larger than range", 4096, 4096, 14, 0, 1},
		{"unpaged", 4096, 8192, 0, 0, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			blob, layout := signedAuditFixture(t, test.offset, test.size, test.shift, 2)
			audits, err := auditCodeDirectories(blob, layout)
			if err != nil {
				t.Fatal(err)
			}
			if len(audits) != 1 || audits[0].FirstSlot != test.first || audits[0].SlotCount != test.checked || audits[0].MatchedSlots != test.checked {
				t.Fatalf("unexpected coverage: %+v", audits)
			}
			blob[layout.cryptOffset+layout.cryptSize-1] ^= 1
			audits, err = auditCodeDirectories(blob, layout)
			if err != nil || audits[0].MatchedSlots != test.checked-1 {
				t.Fatalf("last-byte corruption was not detected: %+v, %v", audits, err)
			}
		})
	}
}

func TestCodeDirectoryHashGeometry(t *testing.T) {
	for _, hashType := range []byte{1, 2, 3, 4} {
		blob, layout := signedAuditFixture(t, 4096, 4096, 12, hashType)
		if _, err := auditCodeDirectories(blob, layout); err != nil {
			t.Fatalf("valid hash type %d: %v", hashType, err)
		}
		directory := blob[int(layout.signatureOffset)+20:]
		directory[36]++
		if _, err := auditCodeDirectories(blob, layout); err == nil {
			t.Fatalf("accepted inconsistent hash length for type %d", hashType)
		}
	}
}

func TestCodeDirectoryRejectsInvalidCoverage(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func([]byte, *machoLayout)
	}{
		{"short code limit", func(dir []byte, _ *machoLayout) { binary.BigEndian.PutUint32(dir[32:], 4096) }},
		{"missing slots", func(dir []byte, _ *machoLayout) { binary.BigEndian.PutUint32(dir[28:], 0) }},
		{"unknown hash", func(dir []byte, _ *machoLayout) { dir[37] = 255 }},
		{"empty encrypted range", func(_ []byte, layout *machoLayout) { layout.cryptSize = 0 }},
		{"out of bounds signature", func(_ []byte, layout *machoLayout) { layout.signatureSize++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			blob, layout := signedAuditFixture(t, 4096, 4096, 12, 2)
			test.change(blob[int(layout.signatureOffset)+20:], &layout)
			if _, err := auditCodeDirectories(blob, layout); err == nil {
				t.Fatal("accepted invalid coverage")
			}
		})
	}
}

func thinHeader(encrypted, signed bool) []byte {
	blob := make([]byte, 32)
	binary.LittleEndian.PutUint32(blob, mhMagic64)
	binary.LittleEndian.PutUint32(blob[4:], 0x100000c)
	commands := uint32(0)
	if encrypted {
		command := make([]byte, 24)
		binary.LittleEndian.PutUint32(command, lcEncryptionInfo64)
		binary.LittleEndian.PutUint32(command[4:], 24)
		binary.LittleEndian.PutUint32(command[8:], 4096)
		binary.LittleEndian.PutUint32(command[12:], 4096)
		binary.LittleEndian.PutUint32(command[16:], 1)
		blob = append(blob, command...)
		commands++
	}
	if signed {
		command := make([]byte, 16)
		binary.LittleEndian.PutUint32(command, lcCodeSignature)
		binary.LittleEndian.PutUint32(command[4:], 16)
		binary.LittleEndian.PutUint32(command[8:], 8192)
		binary.LittleEndian.PutUint32(command[12:], 12)
		blob = append(blob, command...)
		commands++
	}
	binary.LittleEndian.PutUint32(blob[16:], commands)
	binary.LittleEndian.PutUint32(blob[20:], uint32(len(blob)-32))
	return blob
}

func thinARM32Header(encrypted, signed bool) []byte {
	blob := make([]byte, 28)
	binary.LittleEndian.PutUint32(blob, mhMagic32)
	binary.LittleEndian.PutUint32(blob[4:], cpuTypeARM)
	binary.LittleEndian.PutUint32(blob[8:], 9)
	commands := uint32(0)
	if encrypted {
		command := make([]byte, 20)
		binary.LittleEndian.PutUint32(command, lcEncryptionInfo)
		binary.LittleEndian.PutUint32(command[4:], 20)
		binary.LittleEndian.PutUint32(command[8:], 4096)
		binary.LittleEndian.PutUint32(command[12:], 4096)
		binary.LittleEndian.PutUint32(command[16:], 1)
		blob = append(blob, command...)
		commands++
	}
	if signed {
		command := make([]byte, 16)
		binary.LittleEndian.PutUint32(command, lcCodeSignature)
		binary.LittleEndian.PutUint32(command[4:], 16)
		binary.LittleEndian.PutUint32(command[8:], 8192)
		binary.LittleEndian.PutUint32(command[12:], 12)
		blob = append(blob, command...)
		commands++
	}
	binary.LittleEndian.PutUint32(blob[16:], commands)
	binary.LittleEndian.PutUint32(blob[20:], uint32(len(blob)-28))
	return blob
}

func fatARMFixture(t *testing.T) []byte {
	t.Helper()
	const (
		firstOffset  = 4096
		secondOffset = 16384
		sliceSize    = 8204
	)
	blob := make([]byte, secondOffset+sliceSize)
	binary.BigEndian.PutUint32(blob, fatMagic)
	binary.BigEndian.PutUint32(blob[4:], 2)
	entries := []struct {
		offset uint32
		header []byte
		cpu    uint32
		sub    uint32
	}{
		{firstOffset, thinARM32Header(true, true), cpuTypeARM, 9},
		{secondOffset, thinHeader(true, true), cpuTypeARM64, 0},
	}
	for index, entry := range entries {
		arch := blob[8+index*20 : 8+(index+1)*20]
		binary.BigEndian.PutUint32(arch, entry.cpu)
		binary.BigEndian.PutUint32(arch[4:], entry.sub)
		binary.BigEndian.PutUint32(arch[8:], entry.offset)
		binary.BigEndian.PutUint32(arch[12:], sliceSize)
		binary.BigEndian.PutUint32(arch[16:], 12)
		copy(blob[entry.offset:], entry.header)
	}
	return blob
}

func TestMachOEncryptionClassification(t *testing.T) {
	if layout, err := parseThinMachO(thinHeader(false, false), 32); err != nil || layout.cryptID != 0 {
		t.Fatalf("clear image: %+v, %v", layout, err)
	}
	if _, err := parseThinMachO(thinHeader(true, false), 8204); err == nil {
		t.Fatal("accepted encrypted image without a signature")
	}
	if _, err := parseThinMachO(thinHeader(true, true), 8204); err != nil {
		t.Fatal(err)
	}
	armv7, err := parseThinMachO(thinARM32Header(true, true), 8204)
	if err != nil || machoArchitecture(armv7.cpuType, armv7.cpuSubtype) != "armv7" || armv7.cryptID != 1 {
		t.Fatalf("encrypted ARMv7 image: %+v, %v", armv7, err)
	}
	armv6Blob := thinARM32Header(true, true)
	binary.LittleEndian.PutUint32(armv6Blob[8:], 6)
	armv6, err := parseThinMachO(armv6Blob, 8204)
	if err != nil || machoArchitecture(armv6.cpuType, armv6.cpuSubtype) != "armv6" || armv6.cryptID != 1 {
		t.Fatalf("encrypted ARMv6 image: %+v, %v", armv6, err)
	}
	arm64_32 := thinARM32Header(true, true)
	binary.LittleEndian.PutUint32(arm64_32[4:], cpuTypeARM64_32)
	binary.LittleEndian.PutUint32(arm64_32[8:], 1)
	layout, err := parseThinMachO(arm64_32, 8204)
	if err != nil {
		t.Fatal(err)
	}
	if architecture := machoArchitecture(layout.cpuType, layout.cpuSubtype); architecture != "arm64_32" {
		t.Fatalf("architecture = %q, want arm64_32", architecture)
	}
	for _, test := range []struct {
		offset int
		value  uint32
	}{
		{4, 0x1000007}, // Non-ARM64 encrypted image.
		{40, 0},        // Encrypted bytes overlap the load commands.
		{44, 0},        // Empty encrypted range.
		{48, 2},        // Unsupported encryption scheme.
	} {
		blob := thinHeader(true, true)
		binary.LittleEndian.PutUint32(blob[test.offset:], test.value)
		if _, err := parseThinMachO(blob, 8204); err == nil {
			t.Fatalf("accepted unsupported geometry at field %d", test.offset)
		}
	}
}

func TestMachOInstructionSectionInventory(t *testing.T) {
	blob := make([]byte, 32)
	binary.LittleEndian.PutUint32(blob, mhMagic64)
	binary.LittleEndian.PutUint32(blob[4:], cpuTypeARM64)
	segment := make([]byte, 72+2*80)
	binary.LittleEndian.PutUint32(segment, lcSegment64)
	binary.LittleEndian.PutUint32(segment[4:], uint32(len(segment)))
	binary.LittleEndian.PutUint32(segment[64:], 2)
	section := segment[72:]
	copy(section[:16], "__text")
	copy(section[16:32], "__TEXT")
	binary.LittleEndian.PutUint64(section[40:], 0x280)
	binary.LittleEndian.PutUint32(section[48:], 0x1180)
	binary.LittleEndian.PutUint32(section[64:], sectionAttrPureInstructions|sectionAttrSomeInstructions)
	stubHelper := segment[72+80:]
	copy(stubHelper[:16], "__stub_helper")
	copy(stubHelper[16:32], "__TEXT")
	binary.LittleEndian.PutUint64(stubHelper[40:], 0x180)
	binary.LittleEndian.PutUint32(stubHelper[48:], 0x1400)
	binary.LittleEndian.PutUint32(stubHelper[64:], sectionAttrPureInstructions|sectionAttrSomeInstructions)
	blob = append(blob, segment...)

	encryption := make([]byte, 24)
	binary.LittleEndian.PutUint32(encryption, lcEncryptionInfo64)
	binary.LittleEndian.PutUint32(encryption[4:], uint32(len(encryption)))
	binary.LittleEndian.PutUint32(encryption[8:], 4096)
	binary.LittleEndian.PutUint32(encryption[12:], 4096)
	binary.LittleEndian.PutUint32(encryption[16:], 1)
	blob = append(blob, encryption...)
	signature := make([]byte, 16)
	binary.LittleEndian.PutUint32(signature, lcCodeSignature)
	binary.LittleEndian.PutUint32(signature[4:], uint32(len(signature)))
	binary.LittleEndian.PutUint32(signature[8:], 8192)
	binary.LittleEndian.PutUint32(signature[12:], 12)
	blob = append(blob, signature...)
	binary.LittleEndian.PutUint32(blob[16:], 3)
	binary.LittleEndian.PutUint32(blob[20:], uint32(len(blob)-32))

	layout, err := parseThinMachO(blob, 8204)
	if err != nil {
		t.Fatal(err)
	}
	if len(layout.instructionRanges) != 2 || layout.instructionRanges[0] != (machoFileRange{
		offset: 0x1180, size: 0x280, segment: "__TEXT", section: "__text",
		flags: sectionAttrPureInstructions | sectionAttrSomeInstructions,
	}) || layout.instructionRanges[1] != (machoFileRange{
		offset: 0x1400, size: 0x180, segment: "__TEXT", section: "__stub_helper",
		flags: sectionAttrPureInstructions | sectionAttrSomeInstructions,
	}) {
		t.Fatalf("unexpected instruction ranges: %#v", layout.instructionRanges)
	}
}

func TestUniversalMachOEncryptionClassification(t *testing.T) {
	blob := fatARMFixture(t)
	slices, err := parseMachOSlices(blob, uint64(len(blob)))
	if err != nil {
		t.Fatal(err)
	}
	if len(slices) != 2 {
		t.Fatalf("slice count = %d, want 2", len(slices))
	}
	if slices[0].offset != 4096 || slices[0].layout.cpuType != cpuTypeARM || slices[0].layout.cryptID != 1 {
		t.Fatalf("unexpected ARMv7 slice: %+v", slices[0])
	}
	if slices[1].offset != 16384 || slices[1].layout.cpuType != cpuTypeARM64 || slices[1].layout.cryptID != 1 {
		t.Fatalf("unexpected ARM64 slice: %+v", slices[1])
	}
}

func TestUniversalMachORejectsInconsistentGeometry(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func([]byte)
	}{
		{"slice exceeds file", func(blob []byte) { binary.BigEndian.PutUint32(blob[20:], uint32(len(blob))) }},
		{"slice overlaps table", func(blob []byte) { binary.BigEndian.PutUint32(blob[16:], 8) }},
		{"slice architecture mismatch", func(blob []byte) { binary.BigEndian.PutUint32(blob[8:], cpuTypeARM64) }},
		{"slice misaligned", func(blob []byte) { binary.BigEndian.PutUint32(blob[16:], 4097) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			blob := fatARMFixture(t)
			test.change(blob)
			if _, err := parseMachOSlices(blob, uint64(len(blob))); err == nil {
				t.Fatal("accepted malformed universal Mach-O")
			}
		})
	}
}

func TestInventoryRejectsUnclassifiableMachO(t *testing.T) {
	for _, member := range [][]byte{
		thinHeader(true, false),
		{0xca, 0xfe, 0xba, 0xbe}, // Truncated universal Mach-O.
		{0xcf, 0xfa, 0xed, 0xfe},
	} {
		name := filepath.Join(t.TempDir(), "input.ipa")
		file, err := os.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		writer := zip.NewWriter(file)
		entry, err := writer.Create("Payload/Test.app/Test")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(member); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		_, archive, inventoryErr := openIPAInventory(name)
		if archive != nil {
			archive.Close()
		}
		if inventoryErr == nil || !strings.Contains(inventoryErr.Error(), "Payload/Test.app/Test") {
			t.Fatalf("expected explicit member rejection, got %v", inventoryErr)
		}
	}
}
