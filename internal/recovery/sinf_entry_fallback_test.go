package recovery

import (
	"reflect"
	"testing"
)

func newSINFEntryTestState(t *testing.T) (*state, func(uint64, uint64, int)) {
	t.Helper()
	s := newState(&model{pages: make(map[uint64][]byte)})
	s.sp = 0x700000001000
	write := func(address, value uint64, size int) {
		t.Helper()
		for page := address &^ uint64(pageSize-1); page <= (address+uint64(size)-1)&^uint64(pageSize-1); page += pageSize {
			if s.model.pages[page] == nil {
				s.model.pages[page] = make([]byte, pageSize)
			}
		}
		if err := s.storeValue(address, value, size); err != nil {
			t.Fatal(err)
		}
	}
	return s, write
}

func TestSINFEntryDispatch(t *testing.T) {
	const table = uint64(0x710000100000)
	const destination = uint64(0x100484cd0)
	for _, test := range []struct {
		name       string
		selector   uint32
		comparison uint32
		index      int32
		wantEqual  bool
	}{
		{"matching", 0x1234, 0x4440fe62, 0x9667, true},
		{"different", 0x1234, 0x4440fe63, 0x1234, false},
		{"matching-wrap", 0xfffffff0, 0x4440ec1e, -33885, true},
		{"different-wrap", 0xfffffff0, 0x4440ec1f, -16, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			block, ok := compact26A428VerifiedFallbackBlocks[0x1006dd508]
			if !ok {
				t.Fatal("missing SINF entry dispatch block")
			}
			s, write := newSINFEntryTestState(t)
			s.x[10], s.x[11] = uint64(test.comparison), uint64(test.selector)
			write(s.sp+0xdf0, table, 8)
			write(uint64(int64(table)+int64(test.index)*8), destination, 8)
			next, stopped, err := runCompactBlock(s, nil, block)
			if err != nil || stopped || next != destination || s.z != test.wantEqual {
				t.Fatalf("dispatch = %#x, stopped=%v z=%v err=%v", next, stopped, s.z, err)
			}
		})
	}
}

func TestSINFEntrySharedRecordLeaf(t *testing.T) {
	const (
		address    = uint64(0x1003384cc)
		record     = uint64(0x720000001000)
		returnTo   = uint64(0x100020000)
		mask       = uint64(0xee9763edb3ce6674)
		xorMask    = uint64(0xa374c17f4a1aff00)
		multiplier = uint64(0xda51a827)
		pairValue  = uint32(0x11223344)
		otherValue = uint32(0xaabbccdd)
		baseValue  = uint32(0x01020304)
	)
	mixed := record | mask
	mixed -= record & mask
	mixed ^= xorMask
	mixed *= multiplier
	for _, test := range []struct {
		name             string
		bit              uint32
		left, right      uint64
		wantPairSelected bool
	}{
		{"bit-selects-higher", 1, 3, 2, true},
		{"bit-rejects-lower", 1, 2, 3, false},
		{"clear-selects-equal", 0, 2, 2, true},
		{"clear-rejects-different", 0, 2, 3, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, write := newSINFEntryTestState(t)
			s.x[0], s.x[30] = record, returnTo
			write(record, uint64(baseValue+uint32(mixed)), 4)
			write(record+4, uint64(pairValue+uint32(mixed)), 4)
			write(record+8, 0, 4)
			write(record+0x10, test.left+mixed, 8)
			write(record+0x1c, uint64(otherValue^uint32(mixed)), 4)
			write(record+0x20, test.right-mixed, 8)
			write(record+0x28, uint64(test.bit^uint32(mixed)), 4)

			profile := embedded26A428ExecutionProfile()
			block, ok := recoverySINFEntryBlock(s, profile, address)
			if !ok {
				t.Fatal("shared record leaf is unavailable to the SINF-entry CFG")
			}
			next, stopped, err := runCompactBlock(s, nil, block)
			if err != nil || stopped || next != returnTo {
				t.Fatalf("record leaf next=%#x stopped=%v err=%v", next, stopped, err)
			}
			selected := otherValue
			if test.wantPairSelected {
				selected = pairValue
			}
			want := selected ^ baseValue
			got, err := s.load(record+8, 4)
			if err != nil || uint32(got) != want {
				t.Fatalf("record result=%#x err=%v, want %#x", got, err, want)
			}
		})
	}
}

func TestSINFEntrySharedRecordLeafMatchesTracedProfiles(t *testing.T) {
	const address = uint64(0x1003384cc)
	verified, ok := compact26A428VerifiedFallbackBlocks[address]
	if !ok {
		t.Fatal("shared record leaf is missing from the verified fallback")
	}
	for name, blocks := range map[string]map[uint64]compactBlock{
		"account-entry": compact26A428AccountEntryBlocks,
		"bootstrap":     compact26A428BootstrapBlocks,
		"selection":     compact26A428SelectionBlocks,
	} {
		traced, ok := blocks[address]
		if !ok || !reflect.DeepEqual(verified, traced) {
			t.Fatalf("verified shared record leaf differs from %s: %+v", name, traced)
		}
	}
}

func TestSINFEntryFrameCallAndContinuation(t *testing.T) {
	const (
		table        = uint64(0x710000100000)
		context      = uint64(0x720000001000)
		status       = uint64(0x720000002000)
		left         = uint64(0x720000003000)
		right        = uint64(0x720000004000)
		firstTable   = uint64(0x720000005000)
		secondTable  = uint64(0x720000006000)
		callee       = uint64(0x100020000)
		continuation = uint64(0x100030000)
	)
	for _, test := range []struct {
		name                    string
		selector, first, second uint32
	}{
		{"positive-index", 0x1234, 0x520dfad5, 0x376aef66},
		{"negative-index", 0xfffffff0, 0x520e0699, 0x376afda2},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, write := newSINFEntryTestState(t)
			s.x[11], s.x[20], s.x[28] = 0x10, uint64(test.selector), 0x13579bdf
			write(s.sp+0xb100, status, 8)
			write(s.sp+0xb0f8, context, 8)
			write(s.sp+0xdf0, table, 8)
			write(s.sp+0xde8, left, 8)
			write(s.sp+0xde0, right, 8)
			write(s.sp+0xda0, firstTable, 8)
			write(s.sp+0xda8, secondTable, 8)
			write(status, 0x12345678, 4)
			write(context+0x48, 0, 4)
			write(left, 0x102, 4)
			write(right, 0x107, 4)
			write(s.sp+0x11148, 0, 4)
			write(s.sp+0x11150, 0, 4)
			write(table+0x10*8, 0x100796630, 8)
			write(table+0xd03b*8, callee, 8)
			write(uint64(int64(table)+int64(int32(test.selector))*8), continuation, 8)
			for index := uint64(0); index < 256; index++ {
				write(firstTable+index, (index*3+1)&0xff, 1)
				write(secondTable+index, index^0xa5, 1)
			}
			run := func(address, destination uint64) {
				t.Helper()
				block, ok := compact26A428VerifiedFallbackBlocks[address]
				if !ok {
					t.Fatalf("missing SINF entry block %#x", address)
				}
				next, stopped, err := runCompactBlock(s, nil, block)
				if err != nil || stopped || next != destination {
					t.Fatalf("block %#x: next=%#x stopped=%v err=%v", address, next, stopped, err)
				}
			}
			run(0x100484cd0, 0x100796630)
			if got, err := s.load(status, 4); err != nil || got != 0x13345678 {
				t.Fatalf("status = %#x, %v", got, err)
			}
			if got, err := s.load(context+0x48, 4); err != nil || got != 0x13579bdf {
				t.Fatalf("context word = %#x, %v", got, err)
			}
			run(0x100796630, callee)
			if s.x[0] != s.sp+0x11148 || s.x[30] != 0x100796720 {
				t.Fatalf("call frame=%#x return=%#x", s.x[0], s.x[30])
			}
			for address, want := range map[uint64]uint32{s.sp + 0x11148: test.first, s.sp + 0x11150: test.second} {
				if got, err := s.load(address, 4); err != nil || uint32(got) != want {
					t.Fatalf("frame word at %#x = %#x, %v; want %#x", address, got, err, want)
				}
			}
			write(s.sp+0x1114c, 0xdecafbad, 4)
			run(0x100796720, continuation)
			if s.x[8] != 0xdecafbad {
				t.Fatalf("frame result = %#x", s.x[8])
			}
		})
	}
}

// This is an exact-extracted block, not a promoted verified fallback.
func TestExtractedLongSINFEntryPrefix(t *testing.T) {
	blocks, err := loadCompact26A428SafeExtractedBlocks()
	if err != nil {
		t.Fatal(err)
	}
	const address = uint64(0x100254df4)
	block, ok := blocks[address]
	if !ok || len(block.instructions) != 4839 || block.terminator != compactBlockRegister || block.register != 10 {
		t.Fatalf("long entry geometry: ok=%v instructions=%d terminator=%d register=%d", ok, len(block.instructions), block.terminator, block.register)
	}
	if _, ok := compact26A428VerifiedFallbackBlocks[address]; ok {
		t.Fatal("extracted block mislabeled verified")
	}
	s, write := newSINFEntryTestState(t)
	write(s.sp+0x3b8, 0, 4)
	s.x[16] = 0xffff1234
	s.x[12] = 0x12345678
	runtime := &rawSourceRuntime{stopPC: address + 9*4}
	next, stopped, err := runCompactBlock(s, runtime, block)
	if err != nil || !stopped || next != runtime.stopPC {
		t.Fatalf("prefix: %#x %v %v", next, stopped, err)
	}
	product := uint32(0x1234)
	product *= uint32(0x94929381)
	if s.x[14] != 0xffffbe95 || s.x[9] != uint64(product) || s.x[12] != uint64(product&255)^0x7a {
		t.Fatalf("prefix register mismatch")
	}
	stored, err := s.load(s.sp+0x3b8, 4)
	if err != nil || stored != 0x12345678 {
		t.Fatalf("prefix stack write %#x: %v", stored, err)
	}
}

func TestVerifiedSINFStoreLoopTail(t *testing.T) {
	blocks, err := loadCompact26A428SafeExtractedBlocks()
	if err != nil {
		t.Fatal(err)
	}
	block, ok := compact26A428VerifiedFallbackBlocks[0x100392a58]
	if _, overlap := blocks[0x100392a58]; overlap {
		t.Fatal("verified block overlaps extracted")
	}
	if !ok || len(block.instructions) != 3 {
		t.Fatalf("loop tail missing: %v", ok)
	}
	for _, count := range []uint64{1, 2} {
		s, write := newSINFEntryTestState(t)
		const buffer = uint64(0x720000100000)
		write(buffer, 0, 8)
		write(buffer+8, 0, 8)
		s.x[0] = buffer
		s.x[9] = 0x123456789abcdef0
		s.x[10] = count
		next, stopped, err := runCompactBlock(s, nil, block)
		wantNext := uint64(0x100392a40)
		if count == 1 {
			wantNext = 0x100392a68
		}
		if err != nil || stopped || next != wantNext || s.x[0] != buffer+16 || s.x[10] != count-1 || s.z != (count == 1) {
			t.Fatalf("loop tail count=%d next=%#x err=%v", count, next, err)
		}
		for _, offset := range []uint64{0, 8} {
			got, err := s.load(buffer+offset, 8)
			if err != nil || got != 0x123456789abcdef0 {
				t.Fatalf("store %#x err=%v", got, err)
			}
		}
	}
}
