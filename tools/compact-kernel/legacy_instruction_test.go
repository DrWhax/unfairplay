package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/DrWhax/unfairplay/internal/fairplay"
)

func TestTranslateLegacyInstructionForms(t *testing.T) {
	for _, test := range []struct {
		source, opcode string
	}{
		{"sub w14, w3, w14, lsr #1", "compactSubLSR32"},
		{"orr x10, x10, #217020518514230019", "compactLogicalMask64"},
		{"eor x1, x2, #217020518514230019", "compactLogicalMask64"},
		{"and x3, x4, #217020518514230019", "compactLogicalMask64"},
		{"ldr w5, [x6, w5, sxtw]", "compactLoadSXTW32"},
		{"ldr x5, [x6, w5, sxtw]", "compactLoadSXTW64"},
		{"str w5, [x6, w5, sxtw]", "compactStoreSXTW32"},
		{"tst x17, x12", "compactTestRegister64"},
		{"mneg w8, w8, w16", "compactMNeg32"},
		{"mneg x8, x8, x16", "compactMNeg64"},
		{"ror x16, x16, #8", "compactRORImm64"},
		{"ccmp x11, #0x0, #0x4, eq", "compactCCmpImm64"},
		{"eor x0, x17, x0, ror #61", "compactXorROR64"},
		{"uxtl v4.8h, v4.8b", "compactVectorUnsignedShiftLong"},
		{"uxtl2 v18.8h, v17.16b", "compactVectorUnsignedShiftLong"},
		{"sub x11, x11, x11, lsr #16", "compactSubLSR64"},
		{"ldrb w13, [x11, w10, sxtw]", "compactLoadSXTW8"},
		{"ldr q28, [sp, #32]", "compactLoadVector"},
		{"ldp q27, q26, [sp, #720]", "compactPairLoadVector"},
	} {
		got, stop, err := compactInstruction(test.source)
		if err != nil || stop || !strings.Contains(got, test.opcode) {
			t.Fatalf("%q => %q stop=%v err=%v", test.source, got, stop, err)
		}
	}
	if _, _, err := compactInstruction("sub w0, w1, w2, lsr #32"); err == nil {
		t.Fatal("accepted an invalid 32-bit shift")
	}
	if _, _, err := compactLogicalMaskFields("orr", "0", "1", 0x123456789abcdef0); err == nil {
		t.Fatal("accepted an invalid ARM64 logical immediate")
	}
}

func TestExternalMachoBlockExtraction(t *testing.T) {
	path := os.Getenv("UNFAIRPLAY_PROFILE_BINARY")
	if path == "" {
		t.Skip("external FairPlay profile fixture is not configured")
	}
	layout, err := fairplay.InspectFairPlayRecoveryCodeLayout(path)
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := annotatedMachoBlocks(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	expectedStarts := make(map[uint64]bool)
	for _, address := range layout.BasicBlocks {
		expectedStarts[address] = true
	}
	if layout.BinarySHA256 == fairplay.FairPlayBuild26A428Hash {
		expectedStarts[0x100254df4] = true
		expectedStarts[0x1002986d0] = true
	}
	if len(blocks) != len(expectedStarts) {
		t.Fatalf("annotated blocks=%d layout blocks=%d", len(blocks), len(layout.BasicBlocks))
	}
	wanted := map[uint64]bool{}
	switch layout.BinarySHA256 {
	case fairplay.FairPlayBuild26A428Hash:
		wanted[0x1001511f0] = false
		wanted[0x100151304] = false
		wanted[0x1003384cc] = false
	case fairplay.FairPlayBuild26B118Hash:
		wanted[0x10026d170] = false
	default:
		return
	}
	for _, block := range blocks {
		if _, ok := wanted[block.start]; !ok {
			continue
		}
		generated, skipped, _, err := generateCompactCFGSource("selected", []annotatedBlock{block}, 0, true)
		if err != nil || skipped != 0 || !strings.Contains(string(generated), fmt.Sprintf("%#x:", block.start)) {
			t.Fatalf("block %#x was not translated: skipped=%d err=%v", block.start, skipped, err)
		}
		wanted[block.start] = true
	}
	for address, found := range wanted {
		if !found {
			t.Fatalf("missing extracted block %#x", address)
		}
	}
}

func TestExternalSeededMachoExtraction(t *testing.T) {
	path := os.Getenv("UNFAIRPLAY_PROFILE_BINARY")
	if path == "" {
		t.Skip("external FairPlay profile fixture is not configured")
	}
	layout, err := fairplay.InspectFairPlayRecoveryCodeLayout(path)
	if err != nil {
		t.Fatal(err)
	}
	if layout.BinarySHA256 != fairplay.FairPlayBuild26A428Hash {
		t.Skip("seeded extraction geometry is pinned to the 26A428/26A434 image")
	}
	seeds, err := compactProfileStarts("../../internal/recovery/profiles/macos26a428-compact-cfg.bin.gz")
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []uint64{0x1000103a8, 0x1003384cc, 0x100484cd0, 0x1006dd508, 0x100796630, 0x100796720, 0x1007ead40, 0x1007eadc0, 0x1008fe5d4, 0x10093fe44, 0x10093ff14, 0x1009f0994, 0x100392a58} {
		seeds[address] = true
	}
	all, err := annotatedMachoBlocks(path, seeds)
	if err != nil {
		t.Fatal(err)
	}
	blocks := excludeAnnotatedBlocks(all, seeds)
	for _, block := range blocks {
		if block.returnTarget != 0 {
			t.Fatalf("Mach-O block %#x invented fallthrough %#x", block.start, block.returnTarget)
		}
		if seeds[block.start] {
			t.Fatalf("verified block %#x was not excluded", block.start)
		}
	}
	generated, skipped, _, err := generateCompactCFGSource("safeExtracted", blocks, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 59749 || len(all)-len(blocks) != 5530 || strings.Count(string(generated), "start:") != 52494 || skipped != 1725 {
		t.Fatalf("seeded extraction geometry changed: all=%d excluded=%d generated=%d skipped=%d",
			len(all), len(all)-len(blocks), strings.Count(string(generated), "start:"), skipped)
	}
}

func TestSplitMidBlockAuthenticatedCall(t *testing.T) {
	source := `
func rawSourceBlock1000() uint64 {
	// 0x1000: mov x8, #0x2000
	// 0x1004: blraa x8, x17
	// 0x1008: mov x9, #0x3000
	// 0x100c: braa x9, x17
}
`
	blocks, err := parseAnnotatedBlocks(source, "rawSourceBlock")
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 2 || blocks[0].start != 0x1000 || blocks[1].start != 0x1008 {
		t.Fatalf("split blocks: %+v", blocks)
	}
	generated, skipped, _, err := generateCompactCFGSource("testBlocks", blocks, 0, true)
	if err != nil || skipped != 0 {
		t.Fatalf("generate split blocks: skipped=%d err=%v", skipped, err)
	}
	text := string(generated)
	for _, expected := range []string{"0x1000:", "compactBlockCallRegister", "0x1008:", "compactBlockRegister"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("generated split profile lacks %q:\n%s", expected, text)
		}
	}
}

func TestExternalLongSINFEntries(t *testing.T) {
	path := os.Getenv("UNFAIRPLAY_PROFILE_BINARY")
	if path == "" {
		t.Skip("external exact-image fixture is not configured")
	}
	text, base, err := openMachoARM64eText(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		start  uint64
		count  int
		digest string
	}{
		{0x100254df4, 4840, "fa3a0e393971a533d21dbec5b0a8fbd3721c4db684bc4ae555cfcb108d42fa1f"},
		{0x1002986d0, 2114, "52f4139091687c57f242f2c6124ecb9ca4491694346b24ccc3b13173ee66a418"},
	} {
		raw := text[test.start-base : test.start-base+uint64(test.count)*4]
		if fmt.Sprintf("%x", sha256.Sum256(raw)) != test.digest {
			t.Fatalf("entry %#x bytes differ", test.start)
		}
		blocks := annotatedBlocksFromStarts(text, base, []uint64{test.start})
		if len(blocks) != 1 || len(blocks[0].instructions) != test.count {
			t.Fatalf("entry %#x truncated", test.start)
		}
		_, skipped, _, err := generateCompactCFGSource("entry", blocks, 0, true)
		if err != nil || skipped != 0 {
			t.Fatalf("entry %#x translation: skipped=%d err=%v", test.start, skipped, err)
		}
	}
}
