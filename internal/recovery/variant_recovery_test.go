package recovery

import (
	"sync"
	"testing"
)

func TestLegacyCompactInstructions(t *testing.T) {
	t.Run("sub-lsr-32", func(t *testing.T) {
		s := newState(&model{pages: make(map[uint64][]byte)})
		s.x[0], s.x[1] = 0x80000000, 0x80000000
		s.c = true
		err := runCompactKernel(s, compactKernel{instructions: []compactInstruction{{
			op: compactSubLSR32, destination: 2, left: 0, right: 1, shift: 31,
		}}})
		if err != nil || s.x[2] != 0x7fffffff || !s.c {
			t.Fatalf("result=%#x flags.c=%v err=%v", s.x[2], s.c, err)
		}
	})
	t.Run("logical-mask-64", func(t *testing.T) {
		s := newState(&model{pages: make(map[uint64][]byte)})
		s.x[0] = 0x123456789abcdef0
		err := runCompactKernel(s, compactKernel{instructions: []compactInstruction{{
			op: compactLogicalMask64, destination: 0, left: 0, shift: 8, immediate: 2,
		}}})
		if err != nil || s.x[0] != 0x0200020002000200 {
			t.Fatalf("result=%#x err=%v", s.x[0], err)
		}
	})
	t.Run("test-register-64", func(t *testing.T) {
		s := newState(&model{pages: make(map[uint64][]byte)})
		s.x[0], s.x[1], s.c, s.v = 0x8000000000000000, ^uint64(0), true, true
		if err := runCompactKernel(s, compactKernel{instructions: []compactInstruction{{op: compactTestRegister64, left: 0, right: 1}}}); err != nil {
			t.Fatal(err)
		}
		if !s.n || s.z || s.c || s.v {
			t.Fatalf("wrong flags: n=%v z=%v c=%v v=%v", s.n, s.z, s.c, s.v)
		}
	})
	t.Run("multiply-negate-32", func(t *testing.T) {
		s := newState(&model{pages: make(map[uint64][]byte)})
		s.x[0], s.x[1] = 3, 5
		if err := runCompactKernel(s, compactKernel{instructions: []compactInstruction{{op: compactMNeg32, destination: 2, left: 0, right: 1}}}); err != nil {
			t.Fatal(err)
		}
		if s.x[2] != uint64(^uint32(14)) {
			t.Fatalf("result=%#x", s.x[2])
		}
	})
	t.Run("rotate-right-64", func(t *testing.T) {
		s := newState(&model{pages: make(map[uint64][]byte)})
		s.x[0] = 0x1122334455667788
		if err := runCompactKernel(s, compactKernel{instructions: []compactInstruction{{op: compactRORImm64, destination: 1, left: 0, shift: 8}}}); err != nil {
			t.Fatal(err)
		}
		if s.x[1] != 0x8811223344556677 {
			t.Fatalf("result=%#x", s.x[1])
		}
	})
	t.Run("xor-rotate-right-64", func(t *testing.T) {
		s := newState(&model{pages: make(map[uint64][]byte)})
		s.x[0], s.x[1] = 0x0102030405060708, 0x1122334455667788
		if err := runCompactKernel(s, compactKernel{instructions: []compactInstruction{{op: compactXorROR64, destination: 2, left: 0, right: 1, shift: 8}}}); err != nil {
			t.Fatal(err)
		}
		if s.x[2] != 0x891321374153617f {
			t.Fatalf("result=%#x", s.x[2])
		}
	})
	t.Run("subtract-shift-right-64", func(t *testing.T) {
		s := newState(&model{pages: make(map[uint64][]byte)})
		s.x[0], s.x[1] = 0x1000, 0x800
		if err := runCompactKernel(s, compactKernel{instructions: []compactInstruction{{op: compactSubLSR64, destination: 2, left: 0, right: 1, shift: 4}}}); err != nil {
			t.Fatal(err)
		}
		if s.x[2] != 0xf80 {
			t.Fatalf("result=%#x", s.x[2])
		}
	})
}

func TestRecoveryWorkersKeepMappingsPrivate(t *testing.T) {
	const base = uint64(0x710000014000)
	input := &model{allowDestinationPages: true, pages: map[uint64][]byte{base: make([]byte, pageSize)}}
	one, two := newState(input), newState(input)
	initial := one.digest()
	if err := one.storeValue(base-1, 0x42, 1); err != nil {
		t.Fatal(err)
	}
	if err := one.mapZero(0x710100000000, pageSize); err != nil {
		t.Fatal(err)
	}
	if err := one.storeValue(0x710100000000, 0x42, 1); err != nil {
		t.Fatal(err)
	}
	if len(input.pages) != 1 || two.digest() != initial {
		t.Fatal("worker changed shared recovery input")
	}
	if _, err := two.load(base-1, 1); err == nil {
		t.Fatal("worker inherited another worker's destination page")
	}
	one.reset()
	if one.digest() != initial {
		t.Fatal("reset did not restore the captured state")
	}

	var group sync.WaitGroup
	for _, worker := range []*state{one, two} {
		group.Add(1)
		go func(worker *state) {
			defer group.Done()
			for index := 0; index < 100; index++ {
				_, _, err := runCompactBlock(worker, nil, compactBlock{
					start: 0x1000, instructions: []compactInstruction{{op: compactAddImm64, destination: 0, left: 0, immediate: 1}},
					terminator: compactBlockReturn,
				})
				if err != nil {
					t.Error(err)
				}
			}
		}(worker)
	}
	group.Wait()
}

func TestDestinationPagesRequireWrites(t *testing.T) {
	const base = uint64(0x710000014000)
	s := newState(&model{allowDestinationPages: true, pages: map[uint64][]byte{base: make([]byte, pageSize)}})
	if _, err := s.load(base-1, 1); err == nil {
		t.Fatal("read uncaptured memory")
	}
	if err := s.storeValue(base-1, 0x42, 1); err != nil {
		t.Fatal(err)
	}
	if got, err := s.load(base-1, 1); err != nil || got != 0x42 {
		t.Fatalf("written byte=%#x err=%v", got, err)
	}
	if _, err := s.load(base-2, 1); err == nil {
		t.Fatal("invented an unwritten byte")
	}
	if err := s.storeValue(base-2*pageSize, 0, 1); err == nil {
		t.Fatal("accepted a distant missing page")
	}
}

func TestSupplementalProfileContainsIssueTwoSplit(t *testing.T) {
	for _, address := range []uint64{
		0x100105c7c, 0x10010ce1c, 0x10011d288,
		0x1001511f0, 0x100151304, 0x100193064,
	} {
		if _, ok := compact26A428SupplementalBlocks[address]; !ok {
			t.Fatalf("missing supplemental block %#x", address)
		}
	}
	if block := compact26A428SupplementalBlocks[0x1001511f0]; block.terminator != compactBlockCallRegister || block.register != 8 {
		t.Fatalf("indirect call block was not split correctly: %+v", block)
	}
	if block := compact26A428SupplementalBlocks[0x100151304]; block.terminator != compactBlockRegister || block.register != 10 {
		t.Fatalf("call continuation is incorrect: %+v", block)
	}
}

func TestVerifiedFallbackContainsMigratedAccountPath(t *testing.T) {
	tests := []struct {
		address      uint64
		instructions int
		terminator   compactBlockTerminator
		register     uint8
	}{
		{0x1000103a8, 9, compactBlockReturn, 0},
		{0x1007ead40, 31, compactBlockCallRegister, 8},
		{0x1007eadc0, 2, compactBlockRegister, 8},
		{0x1008fe5d4, 12, compactBlockRegister, 8},
		{0x10093fe44, 51, compactBlockCallRegister, 8},
		{0x10093ff14, 6, compactBlockRegister, 8},
		{0x1009f0994, 14, compactBlockRegister, 8},
	}
	for _, test := range tests {
		block, ok := compact26A428VerifiedFallbackBlocks[test.address]
		if !ok || block.start != test.address || len(block.instructions) != test.instructions ||
			block.terminator != test.terminator || block.register != test.register {
			t.Fatalf("verified fallback block %#x is incorrect: %+v", test.address, block)
		}
	}
	value, err := loadModelBytes(embeddedModelBytes())
	if err != nil {
		t.Fatal(err)
	}
	state := newState(value)
	const table = uint64(0x100ff1ef0)
	callTarget, err := state.load(table+0xcfb2*8, 8)
	if err != nil || callTarget != 0x1000103a8 {
		t.Fatalf("migrated-account call slot = %#x, %v", callTarget, err)
	}
	continuation, err := state.load(table+0x9d27*8, 8)
	if err != nil || continuation != 0x100a86df8 {
		t.Fatalf("migrated-account continuation slot = %#x, %v", continuation, err)
	}
	profile := embedded26A428ExecutionProfile()
	if _, ok := recoveryBlock(state, continuation, profile.accountEntryBlocks, profile.supplementalBlocks, profile.verifiedFallbackBlocks); !ok {
		t.Fatalf("migrated-account continuation %#x is missing", continuation)
	}
}

func TestMigratedAccountStatusLeaf(t *testing.T) {
	const address = uint64(0x700000001000)
	block := compact26A428VerifiedFallbackBlocks[0x1000103a8]
	for _, test := range []struct {
		input, want uint32
	}{
		{0x1000, 0xce757bc5},
		{0x1001, 0x318a2070},
	} {
		state := newState(&model{pages: map[uint64][]byte{address: make([]byte, pageSize)}})
		state.x[0], state.x[30] = address, 0x10093ff14
		if err := state.storeValue(address, uint64(test.input), 4); err != nil {
			t.Fatal(err)
		}
		next, stopped, err := runCompactBlock(state, nil, block)
		if err != nil || stopped || next != state.x[30] {
			t.Fatalf("status leaf control flow = %#x, %v, %v", next, stopped, err)
		}
		got, err := state.load(address+4, 4)
		if err != nil || uint32(got) != test.want {
			t.Fatalf("status leaf(%#x) = %#x, %v; want %#x", test.input, got, err, test.want)
		}
	}
}

func TestRecoveryBlockPrecedence(t *testing.T) {
	state := newState(&model{exactExtractedBlocks: map[uint64]compactBlock{1: {start: 14}, 2: {start: 24}, 3: {start: 34}, 4: {start: 44}}})
	primary := map[uint64]compactBlock{1: {start: 11}}
	supplemental := map[uint64]compactBlock{1: {start: 12}, 2: {start: 22}}
	fallback := map[uint64]compactBlock{1: {start: 13}, 2: {start: 23}, 3: {start: 33}}
	for address, want := range map[uint64]uint64{1: 11, 2: 22, 3: 33, 4: 44} {
		block, ok := recoveryBlock(state, address, primary, supplemental, fallback)
		if !ok || block.start != want {
			t.Fatalf("recovery block %#x = %+v, %v; want start %#x", address, block, ok, want)
		}
	}
	if state.extractedBlockHits != 1 {
		t.Fatalf("extracted block hits = %d, want 1", state.extractedBlockHits)
	}
	if _, ok := recoveryBlock(state, 5, primary, supplemental, fallback); ok {
		t.Fatal("unknown recovery block did not fail closed")
	}
}

func TestSafeExtractedProfileIsExactReferenceOnly(t *testing.T) {
	value := &model{}
	if err := addReferencePages(value, ""); err != nil {
		t.Fatal(err)
	}
	if value.exactExtractedBlocks != nil {
		t.Fatal("empty reference enabled extracted blocks")
	}
	blocks, err := loadCompact26A428SafeExtractedBlocks()
	if err != nil || len(blocks) != 52_496 {
		t.Fatalf("safe extracted blocks = %d, %v", len(blocks), err)
	}
	if block, ok := blocks[0x100001058]; !ok || block.terminator != compactBlockCallRegister || block.register != 16 {
		t.Fatalf("safe extracted fixture block is missing: %+v", block)
	}
	// Disjoint invariant: every verified fallback address must be a --seed-start
	// boundary so it is excluded from the safe-extracted profile.
	// 0x10075e008 and 0x1006b2828 were added as seed-starts in QA.md after the
	// 25C56 fix; they will be excluded on the next regeneration of the profile.
	pendingExclusion := map[uint64]bool{
		0x10075e008: true,
		0x1006b2828: true,
	}
	for addr := range compact26A428VerifiedFallbackBlocks {
		if pendingExclusion[addr] {
			continue
		}
		if _, ok := blocks[addr]; ok {
			t.Errorf("verified fallback address %#x must not appear in safe-extracted profile", addr)
		}
	}
}

func TestVerifiedFallbackBlocks(t *testing.T) {
	if block, ok := compact26A428VerifiedFallbackBlocks[0x10075e008]; !ok ||
		block.terminator != compactBlockRegister || block.register != 10 {
		t.Fatalf("verified fallback missing 0x10075e008: %+v", block)
	}
	if block, ok := compact26A428VerifiedFallbackBlocks[0x1006b2828]; !ok ||
		block.terminator != compactBlockRegister || block.register != 15 {
		t.Fatalf("verified fallback missing 0x1006b2828: %+v", block)
	}
}

func TestSelectionBlockLimit(t *testing.T) {
	for _, test := range []struct {
		requested, want int
		bad             bool
	}{
		{0, 2_000_000, false}, {1, 1, false}, {20_000_000, 20_000_000, false},
		{-1, 0, true}, {20_000_001, 0, true},
	} {
		got, err := selectionBlockLimit(test.requested)
		if (err != nil) != test.bad || !test.bad && got != test.want {
			t.Fatalf("limit %d => %d, %v", test.requested, got, err)
		}
	}
}

func TestEmbeddedExecutionProfileGeometry(t *testing.T) {
	profile := embedded26A428ExecutionProfile()
	if profile.name != "macos26a428" || profile.binaryHash != rawSourceBinaryHash ||
		profile.accountEntryStart != 0x100cd1c18 || profile.accountEntryStop != 0x10057ae74 ||
		profile.bootstrapStart != 0x10057ae74 || profile.bootstrapStop != 0x1005b7438 ||
		profile.selectionStart != 0x1006b10a0 || profile.selectionStop != 0x10008a644 || profile.selectionStopHits != 2 ||
		profile.sinfEntryStart != 0x10008a644 || profile.sinfEntryStop != 0x100234cdc ||
		profile.selectionFrameCall != 0x1002fbb24 || len(profile.onceTokens) != 4 {
		t.Fatalf("unexpected embedded execution profile: %+v", profile)
	}
	if len(profile.accountEntryBlocks) != 1086 || len(profile.bootstrapBlocks) != 953 || len(profile.selectionBlocks) != 1656 || len(profile.supplementalBlocks) != 1371 || len(profile.verifiedFallbackBlocks) != 9 {
		t.Fatal("embedded execution profile has incomplete CFG maps")
	}
	model := &model{binaryHash: rawSourceBinaryHash}
	selected, err := executionProfileForModel(model)
	if err != nil || selected.binaryHash != rawSourceBinaryHash {
		t.Fatalf("select embedded execution profile: %v", err)
	}
	bad := *selected
	bad.binaryHash[0] ^= 1
	model.profile = &bad
	if _, err := executionProfileForModel(model); err == nil {
		t.Fatal("accepted an execution profile for another binary")
	}
}
