package fairplay

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const lcBuildVersion = 0x32

// convertDecryptedMachO selects the generic arm64 slice and retargets its
// loader metadata to Mac Catalyst. File offsets and executable code stay fixed.
func convertDecryptedMachO(blob []byte) ([]byte, error) {
	slices, err := parseMachOSlices(blob, uint64(len(blob)))
	if err != nil {
		return nil, err
	}
	var selected *machoSlice
	for i := range slices {
		s := &slices[i]
		if s.layout.cryptID != 0 {
			return nil, fmt.Errorf("Mach-O is still encrypted; decrypt the IPA first")
		}
		if s.layout.cpuType == cpuTypeARM64 && s.layout.cpuSubtype == 0 {
			if selected != nil {
				return nil, fmt.Errorf("multiple generic arm64 slices")
			}
			selected = s
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("Mach-O needs a generic arm64 slice (32-bit and arm64e-only apps are unsupported)")
	}
	out := bytes.Clone(blob[selected.offset : selected.offset+selected.size])
	if binary.LittleEndian.Uint32(out[:4]) != mhMagic64 {
		return nil, fmt.Errorf("expected 64-bit arm64 Mach-O")
	}
	oldEnd := 32 + int(binary.LittleEndian.Uint32(out[20:24]))
	var commands []byte
	versions := 0
	// Only grow into padding bounded by an actual section or file-backed segment.
	dataStart := len(out)
	bounded := false
	for cursor := 32; cursor < oldEnd; {
		size := int(binary.LittleEndian.Uint32(out[cursor+4 : cursor+8]))
		command := bytes.Clone(out[cursor : cursor+size])
		kind := binary.LittleEndian.Uint32(command[:4])
		switch kind {
		case lcSegment64:
			fileoff := binary.LittleEndian.Uint64(command[40:48])
			if fileoff > 0 && fileoff < uint64(dataStart) {
				dataStart = int(fileoff)
				bounded = true
			}
			count := int(binary.LittleEndian.Uint32(command[64:68]))
			for i := 0; i < count; i++ {
				section := command[72+i*80 : 72+(i+1)*80]
				offset := binary.LittleEndian.Uint32(section[48:52])
				sectionType := binary.LittleEndian.Uint32(section[64:68]) & 0xff
				if sectionType != 1 && sectionType != 0xc && sectionType != 0x12 && binary.LittleEndian.Uint64(section[40:48]) > 0 && offset > 0 && uint64(offset) < uint64(dataStart) {
					dataStart = int(offset)
					bounded = true
				}
			}
		case lcBuildVersion, 0x25: // LC_VERSION_MIN_IPHONEOS
			versions++
			if kind == lcBuildVersion {
				if size < 24 || int(binary.LittleEndian.Uint32(command[20:24])) != (size-24)/8 || (size-24)%8 != 0 {
					return nil, fmt.Errorf("invalid build-version command")
				}
				platform := binary.LittleEndian.Uint32(command[8:12])
				if platform != 2 && platform != 6 {
					return nil, fmt.Errorf("unsupported Mach-O platform %d", platform)
				}
			} else if size != 16 {
				return nil, fmt.Errorf("invalid iOS minimum-version command")
			}
			minimum, sdk := uint32(14<<16), uint32(14<<16)
			if kind == lcBuildVersion {
				minimum = max(minimum, binary.LittleEndian.Uint32(command[12:16]))
				sdk = max(minimum, binary.LittleEndian.Uint32(command[16:20]))
			} else {
				minimum = max(minimum, binary.LittleEndian.Uint32(command[8:12]))
				sdk = max(minimum, binary.LittleEndian.Uint32(command[12:16]))
			}
			command = make([]byte, 24)
			binary.LittleEndian.PutUint32(command[0:4], lcBuildVersion)
			binary.LittleEndian.PutUint32(command[4:8], 24)
			binary.LittleEndian.PutUint32(command[8:12], 6) // PLATFORM_MACCATALYST
			binary.LittleEndian.PutUint32(command[12:16], minimum)
			binary.LittleEndian.PutUint32(command[16:20], sdk)
		case 0x24, 0x2f, 0x30: // macOS, tvOS, watchOS legacy commands
			return nil, fmt.Errorf("unsupported Mach-O minimum-version platform")
		case 0xc, 0x80000018: // LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB
			if size < 24 {
				return nil, fmt.Errorf("truncated dylib command")
			}
			nameOffset := int(binary.LittleEndian.Uint32(command[8:12]))
			if nameOffset < 24 || nameOffset >= size || bytes.IndexByte(command[nameOffset:], 0) < 0 {
				return nil, fmt.Errorf("invalid dylib name")
			}
			name := machoName(command[nameOffset:])
			if name == "@rpath/libswiftUIKit.dylib" {
				replacement := "/System/iOSSupport/usr/lib/swift/libswiftUIKit.dylib"
				command = append(bytes.Clone(command[:24]), make([]byte, (len(replacement)+1+7)&^7)...)
				copy(command[24:], replacement)
				binary.LittleEndian.PutUint32(command[4:8], uint32(len(command)))
				binary.LittleEndian.PutUint32(command[8:12], 24)
			}
		}
		commands = append(commands, command...)
		cursor += size
	}
	if versions != 1 {
		return nil, fmt.Errorf("expected exactly one iOS or Catalyst version command")
	}
	newEnd := 32 + len(commands)
	if newEnd > oldEnd {
		if !bounded || newEnd > dataStart || newEnd > len(out) {
			return nil, fmt.Errorf("insufficient bounded Mach-O header padding")
		}
		for _, b := range out[oldEnd:newEnd] {
			if b != 0 {
				return nil, fmt.Errorf("Mach-O header growth would overwrite data")
			}
		}
	}
	clear(out[32:oldEnd])
	copy(out[32:], commands)
	binary.LittleEndian.PutUint32(out[20:24], uint32(len(commands)))
	return out, nil
}
