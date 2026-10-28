package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompactInstruction(t *testing.T) {
	for _, test := range []struct {
		input, want string
		stop        bool
	}{
		{"mov w16, #0x58f20000", "{op: compactMovImm32High, destination: 16, immediate: 0x58f2},", false},
		{"add w15, w15, #0x131, lsl #12", "{op: compactAddImmShift32, destination: 15, left: 15, shift: 12, immediate: 0x131},", false},
		{"eor w8, w8, w9, lsl #1", "{op: compactXorLSL32, destination: 8, left: 8, right: 9, shift: 1},", false},
		{"ldr x8, [x9, w8, sxtw #3]", "{op: compactLoadSXTW64, destination: 8, left: 9, right: 8, shift: 3},", false},
		{"movk x23, #0x2484, lsl #32", "{op: compactMovK64, destination: 23, shift: 32, immediate: 0x2484},", false},
		{"adc w26, wzr, w27", "{op: compactADC32, destination: 26, left: 31, right: 27},", false},
		{"eor w16, w16, #0xffffff87", "{op: compactXorImm32, destination: 16, left: 16, right: 0xff, accumulator: 0xff, immediate: 0xff87},", false},
		{"mov w19, #-0x1080001", "{op: compactMovImm32Wide, destination: 19, right: 0xf7, accumulator: 0xfe, immediate: 0xffff},", false},
		{"mov x6, #0x25800000", "{op: compactMovImm64Shift, destination: 6, shift: 16, immediate: 0x2580},", false},
		{"adrp x9, #0x10106d000", "{op: compactMovImm48, destination: 9, left: 0x6, right: 0x1, accumulator: 0x1, shift: 0x0, immediate: 0xd000},", false},
		{"ldur x8, [x29, #-0x60]", "{op: compactLoadSignedOffset64, destination: 8, left: 29, immediate: 0xffa0},", false},
		{"bic w17, w17, w16, lsl #16", "{op: compactBic32, destination: 17, left: 17, right: 16, shift: 16},", false},
		{"cset w8, ne", "{op: compactCSet32, destination: 8, shift: uint8(compactConditionNE)},", false},
		{"cset w8, cc", "{op: compactCSet32LO, destination: 8},", false},
		{"ldp x28, x27, [sp], #0x60", "{op: compactPairLoad64, destination: 28, left: 31, right: 27, accumulator: 2, immediate: 0x60},", false},
		{"stp x22, x21, [sp, #-0x30]!", "{op: compactPairStore64, destination: 22, left: 31, right: 21, accumulator: 1, immediate: 0xffd0},", false},
		{"ldrb w10, [x11, #0x76a]", "{op: compactLoadBaseImm8, destination: 10, left: 11, immediate: 0x76a},", false},
		{"ldr w10, [x10, w19, sxtw #2]", "{op: compactLoadSXTW32, destination: 10, left: 10, right: 19, shift: 2},", false},
		{"strb wzr, [x16, #0x5af]", "{op: compactStoreBaseImm8, destination: 31, left: 16, immediate: 0x5af},", false},
		{"add x8, x9, w10, sxtw #3", "{op: compactAddExt64, destination: 8, left: 9, right: 10, accumulator: 2, shift: 3},", false},
		{"ccmp x9, x13, #4, ne", "{op: compactCCmpReg64, left: 9, right: 13, accumulator: 4, shift: uint8(compactConditionNE)},", false},
		{"ubfiz w10, w8, #1, #5", "{op: compactUBFIZ32, destination: 10, left: 8, shift: 1, immediate: 0x5},", false},
		{"orn x17, x17, x14, lsl #1", "{op: compactOrNotShift64, destination: 17, left: 17, right: 14, accumulator: 0, shift: 1},", false},
		{"subs x10, x10, #1", "{op: compactSubsImm64, destination: 10, left: 10, immediate: 0x1},", false},
		{"and x11, x11, #0xff00000000000000", "{op: compactAndImmShift64, destination: 11, left: 11, shift: 48, immediate: 0xff00},", false},
		{"eor x16, x15, #0xffe0ffffffffffff", "{op: compactXorNotImm16Shift64, destination: 16, left: 15, shift: 40, immediate: 0x1f00},", false},
		{"mov x10, #-0x4000400040005", "{op: compactMovNegRepeat16PlusOne, destination: 10, immediate: 0x4},", false},
		{"ldr w17, [x23, x17, lsl #2]", "{op: compactLoadXIndexShift32, destination: 17, left: 23, right: 17, shift: 2},", false},
		{"stur xzr, [x29, #-0x90]", "{op: compactStoreSignedOffset64, destination: 31, left: 29, immediate: 0xff70},", false},
		{"and x9, x9, #0xf7ffffffffffffff", "{op: compactAndNotImm16Shift64, destination: 9, left: 9, shift: 48, immediate: 0x800},", false},
		{"casal w11, w12, [x19]", "{op: compactCASAL32, left: 11, right: 12, accumulator: 19},", false},
		{"str w3, [x4], #8", "{op: compactStorePostIndex32, destination: 3, left: 4, immediate: 0x8},", false},
		{"braa x8, x17", "", true},
	} {
		got, stop, err := compactInstruction(test.input)
		if err != nil {
			t.Fatalf("%q: %v", test.input, err)
		}
		if got != test.want || stop != test.stop {
			t.Fatalf("%q = %q, stop=%t; want %q, stop=%t", test.input, got, stop, test.want, test.stop)
		}
	}
}

func TestMachOBlocksDoNotInventFallthrough(t *testing.T) {
	text := make([]byte, 8)
	binary.LittleEndian.PutUint32(text[0:4], 0xd503201f) // nop
	binary.LittleEndian.PutUint32(text[4:8], 0xd65f03c0) // ret
	blocks := annotatedBlocksFromStarts(text, 0x1000, []uint64{0x1000, 0x1004})
	if len(blocks) != 2 || blocks[0].returnTarget != 0 {
		t.Fatalf("unexpected Mach-O blocks: %+v", blocks)
	}
	source, skipped, reasons, err := generateCompactCFGSource("testBlocks", blocks, 0, false)
	if err != nil || skipped != 1 || reasons["terminator nop"] != 1 {
		t.Fatalf("unsafe fallthrough was not rejected: skipped=%d reasons=%v err=%v", skipped, reasons, err)
	}
	textSource := string(source)
	if strings.Contains(textSource, "0x1000:") || !strings.Contains(textSource, "0x1004:") {
		t.Fatalf("unexpected generated blocks:\n%s", textSource)
	}
}

func TestCompactSeedProfileStarts(t *testing.T) {
	var payload bytes.Buffer
	payload.WriteString(compactSeedProfileMagic)
	_ = binary.Write(&payload, binary.LittleEndian, compactSeedProfileVersion)
	_ = binary.Write(&payload, binary.LittleEndian, uint32(1))
	payload.WriteByte(1)
	payload.Write(make([]byte, 7))
	_ = binary.Write(&payload, binary.LittleEndian, uint32(1))
	_ = binary.Write(&payload, binary.LittleEndian, uint32(0))
	_ = binary.Write(&payload, binary.LittleEndian, uint64(0x1000))
	payload.Write(make([]byte, 8))
	_ = binary.Write(&payload, binary.LittleEndian, uint64(0))
	_ = binary.Write(&payload, binary.LittleEndian, uint64(0))
	_ = binary.Write(&payload, binary.LittleEndian, uint32(0))
	_ = binary.Write(&payload, binary.LittleEndian, uint32(0))
	digest := sha256.Sum256(payload.Bytes())
	payload.Write(digest[:])

	path := filepath.Join(t.TempDir(), "seed.bin.gz")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	stream := gzip.NewWriter(file)
	if _, err := stream.Write(payload.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	starts, err := compactProfileStarts(path)
	if err != nil || len(starts) != 1 || !starts[0x1000] {
		t.Fatalf("seed starts = %v, %v", starts, err)
	}
	blocks := []annotatedBlock{{start: 0x1000}, {start: 0x2000}}
	filtered := excludeAnnotatedBlocks(blocks, starts)
	if len(filtered) != 1 || filtered[0].start != 0x2000 {
		t.Fatalf("seed exclusion = %+v", filtered)
	}
}

func TestAddressSetFlag(t *testing.T) {
	values := make(addressSetFlag)
	if err := values.Set("0x2000"); err != nil {
		t.Fatal(err)
	}
	if err := values.Set("4096"); err != nil {
		t.Fatal(err)
	}
	if got := values.String(); got != "0x1000,0x2000" {
		t.Fatalf("address set = %q", got)
	}
	for _, bad := range []string{"0", "3", "nope"} {
		if err := values.Set(bad); err == nil {
			t.Fatalf("accepted invalid seed start %q", bad)
		}
	}
}

func TestCompactBinaryOutputRoundTrip(t *testing.T) {
	blocks := []annotatedBlock{{
		start: 0x1000,
		instructions: []annotatedInstruction{
			{pc: 0x1000, disassembly: "mov w1, #0x42"},
			{pc: 0x1004, disassembly: "ret"},
		},
	}}
	formatted, packed, skipped, reasons, err := generateCompactCFG("", blocks, 0, false)
	if err != nil || formatted != nil || skipped != 0 || len(reasons) != 0 || len(packed) != 1 {
		t.Fatalf("compact translation = source=%d blocks=%d skipped=%d reasons=%v err=%v", len(formatted), len(packed), skipped, reasons, err)
	}
	if len(packed[0].instructions) != 1 || packed[0].instructions[0].op != runtimeCompactOpcodeNumbers["compactMovImm32"] ||
		packed[0].instructions[0].destination != 1 || packed[0].instructions[0].immediate != 0x42 ||
		packed[0].terminator != uint8(runtimeCompactTerminatorNumbers["compactBlockReturn"]) {
		t.Fatalf("unexpected packed block: %+v", packed[0])
	}
	first, err := marshalCompactBlocks(11, packed)
	if err != nil {
		t.Fatal(err)
	}
	second, err := marshalCompactBlocks(11, packed)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("compact output is not deterministic")
	}
	path := filepath.Join(t.TempDir(), "output.bin.gz")
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	starts, err := compactProfileStarts(path)
	if err != nil || len(starts) != 1 || !starts[0x1000] {
		t.Fatalf("packed starts = %v, %v", starts, err)
	}
	if runtimeCompactOpcodeCount != 277 || len(runtimeCompactOpcodeNumbers) != runtimeCompactOpcodeCount ||
		len(runtimeCompactTerminatorNumbers) != 9 || len(runtimeCompactConditionNumbers) != 14 {
		t.Fatal("generated compact constants are incomplete")
	}
}

func TestCompactInstructionRejectsUnknownOperation(t *testing.T) {
	if _, _, err := compactInstruction("svc #0"); err == nil {
		t.Fatal("unsupported instruction was accepted")
	}
}

func TestGenerateCompactSourceKeepsDisjointSegments(t *testing.T) {
	source, err := generateCompactSource("testKernel", []annotatedInstruction{
		{pc: 0x1000, disassembly: "mov w1, #1"},
		{pc: 0x1004, disassembly: "braa x2, x3"},
		{pc: 0x2000, disassembly: "mov w4, #2"},
		{pc: 0x2004, disassembly: "braa x5, x6"},
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, want := range []string{"start: 0x1000", "{index: 1, address: 0x2000}"} {
		if !strings.Contains(text, want) {
			t.Fatalf("generated source lacks %q:\n%s", want, text)
		}
	}
}

func TestGenerateCompactCFGSource(t *testing.T) {
	blocks, err := parseAnnotatedBlocks(`package recovery

func rawSourceAccountEntryBlock1000(s *state, runtime *rawSourceRuntime) (next uint64, stopped bool, err error) {
	// 0x1000: mov w1, #1
	s.x[1] = 1
	// 0x1004: b #0x2000
	return 0x2000, false, nil
}

func rawSourceAccountEntryBlock2000(s *state, runtime *rawSourceRuntime) (next uint64, stopped bool, err error) {
	// 0x2000: cmp w1, w2
	s.compare32(uint32(s.x[1]), uint32(s.x[2]))
	// 0x2004: b.ne #0x3000
	return 0, false, nil
}
`, "rawSourceAccountEntryBlock")
	if err != nil {
		t.Fatal(err)
	}
	source, skipped, reasons, err := generateCompactCFGSource("testBlocks", blocks, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 0 {
		t.Fatalf("skipped %d blocks", skipped)
	}
	if len(reasons) != 0 {
		t.Fatalf("unexpected skip reasons: %v", reasons)
	}
	text := string(source)
	for _, want := range []string{
		"0x1000: {",
		"terminator: compactBlockDirect",
		"target: 0x2000",
		"condition: compactConditionNE",
		"alternate: 0x2008",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("generated CFG lacks %q:\n%s", want, text)
		}
	}
}

func TestPruneCompleteCFGSource(t *testing.T) {
	source, err := pruneCompleteCFGSource(`package recovery

func run(s *state) error {
	for blockCount := 0; blockCount < 1; blockCount++ {
		switch pc {
		case 0x1000:
			{
				return nil
			}
		default:
			return nil
		}
	}
	return nil
}

func rawSourceAccountEntryBlock1000() {
	if true {
		return
	}
}
`, "rawSourceAccountEntryBlock")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if strings.Contains(text, "switch pc") || strings.Contains(text, "rawSourceAccountEntryBlock1000") {
		t.Fatalf("pruned source retained generated CFG:\n%s", text)
	}
	if !strings.Contains(text, "bootstrap CFG reached unknown block") {
		t.Fatalf("pruned source lacks fallback:\n%s", text)
	}
}

func TestLongSINFEntryRequiresRealTerminator(t *testing.T) {
	const start = uint64(0x100254df4)
	text := make([]byte, 4840*4)
	for i := 0; i < len(text); i += 4 {
		binary.LittleEndian.PutUint32(text[i:], 0x52800028)
	}
	binary.LittleEndian.PutUint32(text[len(text)-4:], 0xd65f03c0) // ret
	blocks := annotatedBlocksFromStarts(text, start, []uint64{start})
	if len(blocks) != 1 || len(blocks[0].instructions) != 4840 {
		t.Fatalf("long entry truncated: %d", len(blocks[0].instructions))
	}
	_, skipped, _, err := generateCompactCFGSource("longEntry", blocks, 0, false)
	if err != nil || skipped != 0 {
		t.Fatalf("long entry rejected: %d %v", skipped, err)
	}
	// A nearby unrecognized entry retains the ordinary 512-instruction bound.
	blocks = annotatedBlocksFromStarts(text, start+4, []uint64{start + 4})
	if len(blocks[0].instructions) != 512 {
		t.Fatal("long bound leaked to another entry")
	}
	binary.LittleEndian.PutUint32(text[len(text)-4:], 0x52800028)
	blocks = annotatedBlocksFromStarts(text, start, []uint64{start})
	_, skipped, _, err = generateCompactCFGSource("unterminated", blocks, 0, false)
	if err == nil || skipped != 1 {
		t.Fatalf("unterminated entry accepted: %d %v", skipped, err)
	}
}
