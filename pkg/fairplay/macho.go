package fairplay

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- CodeDirectory compatibility.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
)

const (
	mhMagic32                          = 0xfeedface
	mhMagic64                          = 0xfeedfacf
	mhCigam32                          = 0xcefaedfe
	mhCigam64                          = 0xcffaedfe
	fatMagic                           = 0xcafebabe
	fatCigam                           = 0xbebafeca
	fatMagic64                         = 0xcafebabf
	fatCigam64                         = 0xbfbafeca
	cpuTypeARM                  uint32 = 0x0000000c
	cpuTypeARM64                uint32 = 0x0100000c
	cpuTypeARM64_32             uint32 = 0x0200000c
	lcCodeSignature                    = 0x1d
	lcSegment                          = 0x01
	lcSegment64                        = 0x19
	lcEncryptionInfo                   = 0x21
	lcEncryptionInfo64                 = 0x2c
	sectionAttrPureInstructions        = 0x80000000
	sectionAttrSomeInstructions        = 0x00000400
	csMagicEmbeddedSignature           = 0xfade0cc0
	csMagicCodeDirectory               = 0xfade0c02
)

type machoLayout struct {
	cpuType, cpuSubtype            uint32
	cryptOffset, cryptSize         uint32
	cryptID                        uint32
	cryptIDOffset                  int
	signatureOffset, signatureSize uint32
	instructionRanges              []machoFileRange
}

type machoFileRange struct {
	offset, size     uint64
	segment, section string
	flags            uint32
}

func machoName(value []byte) string {
	if index := bytes.IndexByte(value, 0); index >= 0 {
		value = value[:index]
	}
	return string(value)
}

func sameMachoLayout(left, right machoLayout) bool {
	if left.cpuType != right.cpuType || left.cpuSubtype != right.cpuSubtype ||
		left.cryptOffset != right.cryptOffset || left.cryptSize != right.cryptSize ||
		left.cryptID != right.cryptID || left.cryptIDOffset != right.cryptIDOffset ||
		left.signatureOffset != right.signatureOffset || left.signatureSize != right.signatureSize ||
		len(left.instructionRanges) != len(right.instructionRanges) {
		return false
	}
	for index := range left.instructionRanges {
		if left.instructionRanges[index] != right.instructionRanges[index] {
			return false
		}
	}
	return true
}

type machoSlice struct {
	offset, size uint64
	layout       machoLayout
}

func machoArchitecture(cpuType, cpuSubtype uint32) string {
	switch cpuType {
	case cpuTypeARM:
		switch cpuSubtype & 0xff {
		case 6:
			return "armv6"
		case 9:
			return "armv7"
		case 10:
			return "armv7f"
		case 11:
			return "armv7s"
		case 12:
			return "armv7k"
		case 13:
			return "armv8"
		default:
			return "arm"
		}
	case cpuTypeARM64:
		if cpuSubtype&0xff == 2 {
			return "arm64e"
		}
		return "arm64"
	case cpuTypeARM64_32:
		return "arm64_32"
	default:
		return fmt.Sprintf("cpu-%#x", cpuType)
	}
}

func parseThinMachO(blob []byte, totalSize uint64) (machoLayout, error) {
	var result machoLayout
	if len(blob) < 4 {
		return result, fmt.Errorf("Mach-O header is truncated")
	}
	headerSize := 0
	switch binary.LittleEndian.Uint32(blob[:4]) {
	case mhMagic32:
		headerSize = 28
	case mhMagic64:
		headerSize = 32
	default:
		return result, fmt.Errorf("expected thin little-endian Mach-O")
	}
	if len(blob) < headerSize || totalSize < uint64(headerSize) {
		return result, fmt.Errorf("Mach-O header is truncated")
	}
	result.cpuType = binary.LittleEndian.Uint32(blob[4:8])
	result.cpuSubtype = binary.LittleEndian.Uint32(blob[8:12])
	ncmds := int(binary.LittleEndian.Uint32(blob[16:20]))
	commandsSize := int(binary.LittleEndian.Uint32(blob[20:24]))
	commandsEnd := headerSize + commandsSize
	if commandsEnd < headerSize || commandsEnd > len(blob) || uint64(commandsEnd) > totalSize {
		return result, fmt.Errorf("Mach-O load commands are truncated")
	}
	if ncmds > commandsSize/8 {
		return result, fmt.Errorf("Mach-O load-command count is invalid")
	}
	cursor := headerSize
	encryption, signature := false, false
	for i := 0; i < ncmds; i++ {
		if cursor+8 > commandsEnd {
			return result, fmt.Errorf("Mach-O load command header is truncated")
		}
		command := binary.LittleEndian.Uint32(blob[cursor : cursor+4])
		size := int(binary.LittleEndian.Uint32(blob[cursor+4 : cursor+8]))
		if size < 8 || cursor+size > commandsEnd {
			return result, fmt.Errorf("Mach-O load command has invalid size")
		}
		switch command {
		case lcSegment, lcSegment64:
			segmentHeaderSize, sectionSize, sectionCountOffset := 56, 68, 48
			sectionFileOffset, sectionByteSize, sectionFlagsOffset := 40, 36, 56
			if command == lcSegment64 {
				segmentHeaderSize, sectionSize, sectionCountOffset = 72, 80, 64
				sectionFileOffset, sectionByteSize, sectionFlagsOffset = 48, 40, 64
			}
			if size < segmentHeaderSize {
				return result, fmt.Errorf("Mach-O segment command is truncated")
			}
			sectionCount := int(binary.LittleEndian.Uint32(blob[cursor+sectionCountOffset : cursor+sectionCountOffset+4]))
			if sectionCount > (size-segmentHeaderSize)/sectionSize || segmentHeaderSize+sectionCount*sectionSize != size {
				return result, fmt.Errorf("Mach-O segment section table is invalid")
			}
			for sectionIndex := 0; sectionIndex < sectionCount; sectionIndex++ {
				section := blob[cursor+segmentHeaderSize+sectionIndex*sectionSize : cursor+segmentHeaderSize+(sectionIndex+1)*sectionSize]
				flags := binary.LittleEndian.Uint32(section[sectionFlagsOffset : sectionFlagsOffset+4])
				if flags&(sectionAttrPureInstructions|sectionAttrSomeInstructions) == 0 {
					continue
				}
				offset := uint64(binary.LittleEndian.Uint32(section[sectionFileOffset : sectionFileOffset+4]))
				var sectionBytes uint64
				if command == lcSegment64 {
					sectionBytes = binary.LittleEndian.Uint64(section[sectionByteSize : sectionByteSize+8])
				} else {
					sectionBytes = uint64(binary.LittleEndian.Uint32(section[sectionByteSize : sectionByteSize+4]))
				}
				if sectionBytes == 0 {
					continue
				}
				if offset > totalSize || sectionBytes > totalSize-offset {
					return result, fmt.Errorf("Mach-O instruction section exceeds file")
				}
				candidate := machoFileRange{
					offset: offset, size: sectionBytes,
					section: machoName(section[:16]), segment: machoName(section[16:32]), flags: flags,
				}
				for _, previous := range result.instructionRanges {
					if candidate.offset < previous.offset+previous.size && previous.offset < candidate.offset+candidate.size {
						return result, fmt.Errorf("Mach-O instruction sections overlap")
					}
				}
				result.instructionRanges = append(result.instructionRanges, candidate)
			}
		case lcEncryptionInfo, lcEncryptionInfo64:
			minimum := 20
			if command == lcEncryptionInfo64 {
				minimum = 24
			}
			if size < minimum || encryption {
				return result, fmt.Errorf("Mach-O encryption command is invalid")
			}
			result.cryptOffset = binary.LittleEndian.Uint32(blob[cursor+8 : cursor+12])
			result.cryptSize = binary.LittleEndian.Uint32(blob[cursor+12 : cursor+16])
			result.cryptID = binary.LittleEndian.Uint32(blob[cursor+16 : cursor+20])
			result.cryptIDOffset = cursor + 16
			encryption = true
		case lcCodeSignature:
			if size < 16 || signature {
				return result, fmt.Errorf("Mach-O code-signature command is invalid")
			}
			result.signatureOffset = binary.LittleEndian.Uint32(blob[cursor+8 : cursor+12])
			result.signatureSize = binary.LittleEndian.Uint32(blob[cursor+12 : cursor+16])
			signature = true
		}
		cursor += size
	}
	if cursor != commandsEnd {
		return result, fmt.Errorf("Mach-O load commands do not fill header")
	}
	if !encryption || result.cryptID == 0 {
		return result, nil
	}
	magic := binary.LittleEndian.Uint32(blob[:4])
	if result.cryptID != 1 || magic == mhMagic32 && result.cpuType != cpuTypeARM && result.cpuType != cpuTypeARM64_32 || magic == mhMagic64 && result.cpuType != cpuTypeARM64 {
		return result, fmt.Errorf("unsupported encrypted Mach-O architecture or cryptid")
	}
	if !signature {
		return result, fmt.Errorf("Mach-O has no code-signature command")
	}
	if uint64(result.cryptOffset)+uint64(result.cryptSize) > totalSize || uint64(result.signatureOffset)+uint64(result.signatureSize) > totalSize {
		return result, fmt.Errorf("Mach-O range exceeds file")
	}
	if result.cryptSize == 0 || result.cryptSize%pageBytes != 0 || result.cryptOffset%pageBytes != 0 {
		return result, fmt.Errorf("Mach-O encrypted range must be nonempty and 4 KiB aligned")
	}
	if uint64(result.cryptOffset) < uint64(commandsEnd) || uint64(result.cryptOffset)+uint64(result.cryptSize) > uint64(result.signatureOffset) {
		return result, fmt.Errorf("Mach-O encrypted range overlaps headers or signature")
	}
	return result, nil
}

func isFatMachO(blob []byte) bool {
	if len(blob) < 4 {
		return false
	}
	switch binary.BigEndian.Uint32(blob[:4]) {
	case fatMagic, fatCigam, fatMagic64, fatCigam64:
		return true
	default:
		return false
	}
}

func isKnownUnsupportedMachO(blob []byte) bool {
	if len(blob) < 4 {
		return false
	}
	switch binary.LittleEndian.Uint32(blob[:4]) {
	case mhCigam32, mhCigam64:
		return true
	default:
		return false
	}
}

func parseMachOSlices(blob []byte, totalSize uint64) ([]machoSlice, error) {
	if len(blob) < 4 {
		return nil, fmt.Errorf("Mach-O header is truncated")
	}
	switch binary.LittleEndian.Uint32(blob[:4]) {
	case mhMagic32, mhMagic64:
		layout, err := parseThinMachO(blob, totalSize)
		if err != nil {
			return nil, err
		}
		return []machoSlice{{size: totalSize, layout: layout}}, nil
	case mhCigam32, mhCigam64:
		return nil, fmt.Errorf("big-endian thin Mach-O is unsupported")
	}
	if !isFatMachO(blob) {
		return nil, fmt.Errorf("expected Mach-O image")
	}
	if uint64(len(blob)) != totalSize {
		return nil, fmt.Errorf("universal Mach-O must be read completely")
	}
	magic := binary.BigEndian.Uint32(blob[:4])
	var order binary.ByteOrder = binary.BigEndian
	if magic == fatCigam || magic == fatCigam64 {
		order = binary.LittleEndian
	}
	is64 := magic == fatMagic64 || magic == fatCigam64
	entrySize := 20
	if is64 {
		entrySize = 32
	}
	if len(blob) < 8 {
		return nil, fmt.Errorf("universal Mach-O header is truncated")
	}
	count := int(order.Uint32(blob[4:8]))
	if count == 0 || count > 32 || count > (len(blob)-8)/entrySize {
		return nil, fmt.Errorf("universal Mach-O architecture count is invalid")
	}
	tableEnd := uint64(8 + count*entrySize)
	slices := make([]machoSlice, 0, count)
	for index := 0; index < count; index++ {
		entry := blob[8+index*entrySize : 8+(index+1)*entrySize]
		cpuType, cpuSubtype := order.Uint32(entry[:4]), order.Uint32(entry[4:8])
		var offset, size uint64
		if is64 {
			offset, size = order.Uint64(entry[8:16]), order.Uint64(entry[16:24])
		} else {
			offset, size = uint64(order.Uint32(entry[8:12])), uint64(order.Uint32(entry[12:16]))
		}
		alignOffset := 16
		if is64 {
			alignOffset = 24
		}
		align := order.Uint32(entry[alignOffset : alignOffset+4])
		if size == 0 || offset < tableEnd || offset > totalSize || size > totalSize-offset {
			return nil, fmt.Errorf("universal Mach-O architecture %d has invalid bounds", index)
		}
		if align > 63 || offset&((uint64(1)<<align)-1) != 0 {
			return nil, fmt.Errorf("universal Mach-O architecture %d is misaligned", index)
		}
		for _, previous := range slices {
			if offset < previous.offset+previous.size && previous.offset < offset+size {
				return nil, fmt.Errorf("universal Mach-O architectures overlap")
			}
		}
		layout, err := parseThinMachO(blob[offset:offset+size], size)
		if err != nil {
			return nil, fmt.Errorf("universal Mach-O architecture %d: %w", index, err)
		}
		if layout.cpuType != cpuType || layout.cpuSubtype != cpuSubtype {
			return nil, fmt.Errorf("universal Mach-O architecture %d does not match its slice", index)
		}
		slices = append(slices, machoSlice{offset: offset, size: size, layout: layout})
	}
	return slices, nil
}

type codeDirectoryAudit struct {
	HashType     byte `json:"hash_type"`
	HashSize     int  `json:"hash_size"`
	PageSize     int  `json:"page_size"`
	FirstSlot    int  `json:"first_slot"`
	SlotCount    int  `json:"slot_count"`
	MatchedSlots int  `json:"matched_slots"`
}

func hashCodePage(hashType byte, payload []byte) ([]byte, error) {
	switch hashType {
	case 1:
		v := sha1.Sum(payload)
		return v[:], nil
	case 2, 3:
		v := sha256.Sum256(payload)
		return v[:], nil
	case 4:
		v := sha512.Sum384(payload)
		return v[:], nil
	}
	return nil, fmt.Errorf("unsupported CodeDirectory hash type %d", hashType)
}

func auditCodeDirectories(executable []byte, layout machoLayout) ([]codeDirectoryAudit, error) {
	return auditCodeDirectoriesMode(executable, layout, false)
}

// auditPreEncryptionCodeDirectories compares the candidate plaintext with the
// available pre-encryption hashes in embedded CodeDirectories. A genuinely
// absent table is skipped; ordinary code hashes are not a substitute.
func auditPreEncryptionCodeDirectories(executable []byte, layout machoLayout) ([]codeDirectoryAudit, error) {
	return auditCodeDirectoriesMode(executable, layout, true)
}

func auditCodeDirectoriesMode(executable []byte, layout machoLayout, preEncryption bool) ([]codeDirectoryAudit, error) {
	signatureEnd := uint64(layout.signatureOffset) + uint64(layout.signatureSize)
	cryptEnd := uint64(layout.cryptOffset) + uint64(layout.cryptSize)
	if signatureEnd > uint64(len(executable)) || cryptEnd > uint64(len(executable)) || layout.cryptSize == 0 {
		return nil, fmt.Errorf("invalid Mach-O audit ranges")
	}
	sig := executable[uint64(layout.signatureOffset):signatureEnd]
	if len(sig) < 12 || binary.BigEndian.Uint32(sig[:4]) != csMagicEmbeddedSignature {
		return nil, fmt.Errorf("invalid embedded signature")
	}
	total, count := int(binary.BigEndian.Uint32(sig[4:8])), int(binary.BigEndian.Uint32(sig[8:12]))
	if total > len(sig) || 12+count*8 > total {
		return nil, fmt.Errorf("invalid embedded signature geometry")
	}
	reports := make([]codeDirectoryAudit, 0)
	directories := 0
	for i := 0; i < count; i++ {
		offset := int(binary.BigEndian.Uint32(sig[16+i*8 : 20+i*8]))
		if offset+8 > total {
			return nil, fmt.Errorf("signature item exceeds superblob")
		}
		magic, length := binary.BigEndian.Uint32(sig[offset:offset+4]), int(binary.BigEndian.Uint32(sig[offset+4:offset+8]))
		if length < 8 || offset+length > total {
			return nil, fmt.Errorf("signature item has invalid length")
		}
		if magic != csMagicCodeDirectory {
			continue
		}
		directories++
		dir := sig[offset : offset+length]
		if len(dir) < 44 {
			return nil, fmt.Errorf("CodeDirectory is truncated")
		}
		version := binary.BigEndian.Uint32(dir[8:12])
		headerSize := 44
		if version >= 0x20100 {
			headerSize = 48
			if len(dir) < headerSize || binary.BigEndian.Uint32(dir[44:48]) != 0 {
				return nil, fmt.Errorf("truncated or unsupported scattered CodeDirectory")
			}
		}
		if version >= 0x20200 {
			headerSize = 52
		}
		if version >= 0x20300 {
			headerSize = 64
		}
		if version >= 0x20400 {
			headerSize = 88
		}
		if version >= 0x20500 {
			headerSize = 96
		}
		if version >= 0x20600 {
			headerSize = 108
		}
		if len(dir) < headerSize {
			return nil, fmt.Errorf("extended CodeDirectory is truncated")
		}
		codeLimit := uint64(binary.BigEndian.Uint32(dir[32:36]))
		if version >= 0x20300 {
			if codeLimit == 0 {
				codeLimit = binary.BigEndian.Uint64(dir[56:64])
			}
		}
		hashOffset := uint64(binary.BigEndian.Uint32(dir[16:20]))
		codeSlots := uint64(binary.BigEndian.Uint32(dir[28:32]))
		hashSize := int(dir[36])
		hashType := dir[37]
		shift := dir[39]
		expectedSize := map[byte]int{1: 20, 2: 32, 3: 20, 4: 48}[hashType]
		if expectedSize == 0 || hashSize != expectedSize || shift > 30 {
			return nil, fmt.Errorf("CodeDirectory geometry is invalid")
		}
		if codeLimit < cryptEnd || codeLimit > uint64(len(executable)) {
			return nil, fmt.Errorf("CodeDirectory does not cover encrypted range")
		}
		pageSize := uint64(1) << shift
		if shift == 0 {
			pageSize = codeLimit // An unpaged CodeDirectory hashes the entire code region.
		}
		firstSlot := uint64(layout.cryptOffset) / pageSize
		lastSlot := (cryptEnd + pageSize - 1) / pageSize
		slots := lastSlot - firstSlot
		if codeSlots != (codeLimit+pageSize-1)/pageSize || lastSlot > codeSlots || hashOffset < uint64(headerSize) || hashOffset+codeSlots*uint64(hashSize) > uint64(len(dir)) {
			return nil, fmt.Errorf("CodeDirectory table is truncated")
		}
		if preEncryption {
			if version < 0x20500 {
				continue
			}
			preOffset := uint64(binary.BigEndian.Uint32(dir[92:96]))
			if preOffset == 0 {
				continue
			}
			if preOffset < uint64(headerSize) || preOffset > uint64(len(dir)) || codeSlots*uint64(hashSize) > uint64(len(dir))-preOffset {
				return nil, fmt.Errorf("CodeDirectory pre-encryption table is invalid or truncated")
			}
			hashOffset = preOffset
		}
		matched := 0
		for slot := firstSlot; slot < lastSlot; slot++ {
			start := slot * pageSize
			end := min(start+pageSize, codeLimit)
			actual, err := hashCodePage(hashType, executable[start:end])
			if err != nil {
				return nil, err
			}
			expected := dir[hashOffset+slot*uint64(hashSize) : hashOffset+(slot+1)*uint64(hashSize)]
			if bytes.Equal(actual[:hashSize], expected) {
				matched++
			}
		}
		reports = append(reports, codeDirectoryAudit{hashType, hashSize, int(pageSize), int(firstSlot), int(slots), matched})
	}
	if directories == 0 {
		return nil, fmt.Errorf("embedded signature contains no CodeDirectory")
	}
	return reports, nil
}
