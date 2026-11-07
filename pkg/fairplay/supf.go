package fairplay

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"path"
)

type supfArchitecture struct {
	cpuType, cpuSubtype uint32
	records             [][32]byte
	SignatureSHA1       [20]byte
	HasSignatureSHA1    bool
}

type supf struct {
	architectures             []supfArchitecture
	variant                   byte
	UniversalSignatureSHA1    [20]byte
	HasUniversalSignatureSHA1 bool
}

// ValidateUniversalSignatureBinding checks a legacy SUPP hash over the
// concatenated slice-relative LC_CODE_SIGNATURE payloads in fat-header order.
func (s supf) ValidateUniversalSignatureBinding(executable []byte, slices []machoSlice) error {
	if !s.HasUniversalSignatureSHA1 {
		return nil
	}
	hash := sha1.New() // #nosec G401 -- legacy SUPP compatibility.
	count := 0
	for _, slice := range slices {
		start := slice.offset + uint64(slice.layout.signatureOffset)
		size := uint64(slice.layout.signatureSize)
		sliceEnd := slice.offset + slice.size
		if size == 0 || start < slice.offset || sliceEnd < slice.offset || start > uint64(len(executable)) || size > uint64(len(executable))-start || start+size > sliceEnd {
			return fmt.Errorf("SUPP universal signature binding has invalid slice extent")
		}
		_, _ = hash.Write(executable[start : start+size])
		count++
	}
	if count == 0 || !bytes.Equal(hash.Sum(nil), s.UniversalSignatureSHA1[:]) {
		return fmt.Errorf("SUPP universal signature binding mismatch")
	}
	return nil
}

func parseSUPF(blob []byte) (supf, error) {
	var result supf
	if len(blob) < 12 {
		return result, fmt.Errorf("SUPF is truncated")
	}
	variant := blob[0]
	if variant != 3 && variant != 5 {
		return result, fmt.Errorf("unsupported SUPF variant %d", variant)
	}
	result.variant = variant
	outerEnd := 8 + int(binary.BigEndian.Uint32(blob[4:8]))
	if outerEnd > len(blob) {
		return result, fmt.Errorf("SUPF outer payload exceeds file")
	}
	count := int(binary.BigEndian.Uint32(blob[8:12]))
	if count == 0 || count > 32 {
		return result, fmt.Errorf("SUPF architecture count is invalid")
	}
	seen := make(map[[2]uint32]bool)
	cursor := 12
	for i := 0; i < count; i++ {
		if cursor+4 > outerEnd {
			return result, fmt.Errorf("SUPF architecture length is truncated")
		}
		length := int(binary.BigEndian.Uint32(blob[cursor : cursor+4]))
		start, end := cursor+4, cursor+4+length
		if start+8 > end || end > outerEnd {
			return result, fmt.Errorf("SUPF architecture has invalid geometry")
		}
		arch := supfArchitecture{cpuType: binary.BigEndian.Uint32(blob[start : start+4]), cpuSubtype: binary.BigEndian.Uint32(blob[start+4 : start+8])}
		id := [2]uint32{arch.cpuType, arch.cpuSubtype}
		if seen[id] {
			return supf{}, fmt.Errorf("duplicate SUPF architecture %#x/%#x", id[0], id[1])
		}
		seen[id] = true
		payload := start + 8
		if variant == 3 {
			if end-payload < 20 {
				return supf{}, fmt.Errorf("SUPF signature hash is truncated")
			}
			copy(arch.SignatureSHA1[:], blob[payload:payload+20])
			arch.HasSignatureSHA1 = true
			payload += 20
		}
		if payload+4 > end {
			return result, fmt.Errorf("SUPF page count is truncated")
		}
		pages := int(binary.BigEndian.Uint32(blob[payload : payload+4]))
		keys := payload + 4
		if keys+pages*32 != end {
			return result, fmt.Errorf("SUPF page-key table has inconsistent length")
		}
		arch.records = make([][32]byte, pages)
		for page := 0; page < pages; page++ {
			copy(arch.records[page][:], blob[keys+page*32:keys+(page+1)*32])
		}
		result.architectures = append(result.architectures, arch)
		cursor = end
	}
	if cursor != outerEnd {
		return result, fmt.Errorf("SUPF records do not fill outer payload")
	}
	return result, nil
}

func (s supf) recordsFor(cpuType, cpuSubtype uint32) ([][32]byte, error) {
	for _, arch := range s.architectures {
		if arch.cpuType == cpuType && arch.cpuSubtype == cpuSubtype {
			return arch.records, nil
		}
	}
	return nil, fmt.Errorf("SUPF has no matching architecture %#x/%#x", cpuType, cpuSubtype)
}

// ValidateSignatureBinding checks the selected architecture when the legacy
// format supplies a code-signature binding, including an equivalent v5 alias.
func (s supf) ValidateSignatureBinding(executable []byte, layout machoLayout) error {
	for _, arch := range s.architectures {
		if arch.cpuType == layout.cpuType && arch.cpuSubtype == layout.cpuSubtype {
			if arch.HasSignatureSHA1 {
				return validateSUPFSignatureBinding(executable, layout, arch.SignatureSHA1)
			}
			return nil
		}
	}
	return fmt.Errorf("SUPF signature binding has no matching architecture")
}

// validateSUPFSignatureBinding checks the whole slice-relative
// LC_CODE_SIGNATURE payload against the v3 architecture's SHA-1 binding.
func validateSUPFSignatureBinding(executable []byte, layout machoLayout, expected [20]byte) error {
	start, size := uint64(layout.signatureOffset), uint64(layout.signatureSize)
	if size == 0 || start > uint64(len(executable)) || size > uint64(len(executable))-start {
		return fmt.Errorf("SUPF signature binding has invalid signature extent")
	}
	actual := sha1.Sum(executable[start : start+size])
	if actual != expected {
		return fmt.Errorf("SUPF signature binding mismatch")
	}
	return nil
}

// selectSUPF compares both adjacent variants and preserves a v3 signature
// binding on the canonical v5 result. It does not fall back after invalid data.
func selectSUPF(files map[string]*zip.File, member string) (string, supf, error) {
	base := path.Join(path.Dir(member), "SC_Info", path.Base(member))
	names := [2]string{base + ".supf", base + ".v5.supf"}
	var parsed [2]supf
	var present [2]bool
	var emptyLegacy bool
	for i, name := range names {
		file, ok := files[name]
		if !ok {
			continue
		}
		if file == nil {
			return "", supf{}, fmt.Errorf("invalid SUPF member %q", name)
		}
		data, err := zipBytes(file)
		if err != nil {
			return "", supf{}, fmt.Errorf("read SUPF %q: %w", name, err)
		}
		if len(data) == 0 && i == 0 {
			emptyLegacy = true
			continue
		}
		parsed[i], err = parseSUPF(data)
		clear(data)
		if err != nil {
			return "", supf{}, fmt.Errorf("invalid SUPF %q: %w", name, err)
		}
		expected := byte(3)
		if i == 1 {
			expected = 5
		}
		if parsed[i].variant != expected {
			return "", supf{}, fmt.Errorf("SUPF %q has variant %d, expected %d", name, parsed[i].variant, expected)
		}
		present[i] = true
	}
	if emptyLegacy && !present[1] {
		return "", supf{}, fmt.Errorf("empty legacy SUPF requires valid v5 SUPF")
	}
	if !present[0] && !present[1] {
		return "", supf{}, fmt.Errorf("encrypted Mach-O %q has no adjacent SUPF", member)
	}
	if present[0] && present[1] {
		if len(parsed[0].architectures) != len(parsed[1].architectures) {
			return "", supf{}, fmt.Errorf("SUPF variants have different architecture sets")
		}
		old := make(map[[2]uint32]supfArchitecture, len(parsed[0].architectures))
		for _, a := range parsed[0].architectures {
			old[[2]uint32{a.cpuType, a.cpuSubtype}] = a
		}
		for i := range parsed[1].architectures {
			a := &parsed[1].architectures[i]
			v, ok := old[[2]uint32{a.cpuType, a.cpuSubtype}]
			if !ok || len(a.records) != len(v.records) {
				return "", supf{}, fmt.Errorf("SUPF variants have different architecture sets or page counts")
			}
			for j := range a.records {
				if !bytes.Equal(a.records[j][:], v.records[j][:]) {
					return "", supf{}, fmt.Errorf("SUPF variants have different page records")
				}
			}
			a.SignatureSHA1 = v.SignatureSHA1
			a.HasSignatureSHA1 = true
		}
	}
	if present[1] {
		return names[1], parsed[1], nil
	}
	return names[0], parsed[0], nil
}
