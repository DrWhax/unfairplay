package fairplay

import (
	"archive/zip"
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"path"

	"github.com/DrWhax/unfairplay/internal/scinfo"
)

// supp records describe pages beginning at file offset zero, including pages
// before the encrypted range. Version 1 binds the complete code signature.
type supp struct {
	variant          byte
	records          [][32]byte
	SignatureSHA1    [20]byte
	HasSignatureSHA1 bool
}

// parseSUPPWithCA allows synthetic fixtures to use an explicit public CA.
// Production callers use the pinned authority in scinfo.
func parseSUPPWithCA(blob []byte, authority *rsa.PublicKey) (supp, error) {
	var result supp
	if len(blob) < 8 {
		return result, fmt.Errorf("SUPP is truncated")
	}
	result.variant = blob[0]
	if result.variant != 1 && result.variant != 4 {
		return supp{}, fmt.Errorf("unsupported SUPP variant %d", result.variant)
	}
	cursor := 4
	if result.variant == 1 {
		if len(blob)-cursor < 20+4 {
			return supp{}, fmt.Errorf("SUPP signature hash is truncated")
		}
		copy(result.SignatureSHA1[:], blob[cursor:cursor+20])
		result.HasSignatureSHA1 = true
		cursor += 20
	}
	if len(blob)-cursor < 4 {
		return supp{}, fmt.Errorf("SUPP page count is truncated")
	}
	pages := uint64(binary.BigEndian.Uint32(blob[cursor : cursor+4]))
	cursor += 4
	// Bound the multiplication and allocation by the remaining input before
	// converting to int. Leave room for certificate length and RSA signature.
	if pages == 0 || len(blob)-cursor < 4+128 || pages > uint64((len(blob)-cursor-4-128)/32) {
		return supp{}, fmt.Errorf("SUPP page records have invalid geometry")
	}
	end := cursor + int(pages)*32
	signedPrefix := blob[:end]
	certificateBytes := uint64(binary.BigEndian.Uint32(blob[end : end+4]))
	certStart := end + 4
	if certificateBytes == 0 || certificateBytes != uint64(len(blob)-certStart-128) {
		return supp{}, fmt.Errorf("SUPP certificate and signature have invalid geometry")
	}
	certEnd := certStart + int(certificateBytes)
	if err := scinfo.VerifyEnvelope(result.variant, signedPrefix, blob[certStart:certEnd], blob[certEnd:], authority); err != nil {
		return supp{}, fmt.Errorf("SUPP envelope: %w", err)
	}
	result.records = make([][32]byte, int(pages))
	for i := range result.records {
		copy(result.records[i][:], blob[cursor+i*32:cursor+(i+1)*32])
	}
	return result, nil
}

// recordsForLayout maps the file-origin table to the encrypted page range.
func (s supp) recordsForLayout(layout machoLayout) ([][32]byte, error) {
	const page = uint64(4096)
	start, size := uint64(layout.cryptOffset), uint64(layout.cryptSize)
	if size == 0 || start%page != 0 || size%page != 0 {
		return nil, fmt.Errorf("SUPP encrypted range is not page aligned")
	}
	end := start + size
	if uint64(len(s.records)) != end/page {
		return nil, fmt.Errorf("SUPP record count does not match encrypted range")
	}
	return s.records[start/page:], nil
}

// architecturesForSlices maps one file-origin SUPP table onto every encrypted
// slice. Thin tables end at the encrypted range. Universal tables use absolute
// file offsets and end at the final encrypted range.
func (s supp) architecturesForSlices(slices []machoSlice) ([]supfArchitecture, error) {
	if len(slices) == 0 {
		return nil, fmt.Errorf("SUPP has no Mach-O slices")
	}
	if len(slices) == 1 && slices[0].offset == 0 {
		records, err := s.recordsForLayout(slices[0].layout)
		if err != nil {
			return nil, err
		}
		layout := slices[0].layout
		return []supfArchitecture{{
			cpuType: layout.cpuType, cpuSubtype: layout.cpuSubtype, records: records,
			SignatureSHA1: s.SignatureSHA1, HasSignatureSHA1: s.HasSignatureSHA1,
		}}, nil
	}

	const page = uint64(4096)
	var encrypted []machoSlice
	var lastEnd uint64
	seen := make(map[[2]uint32]bool)
	for _, slice := range slices {
		layout := slice.layout
		if layout.cryptID == 0 {
			continue
		}
		start := slice.offset + uint64(layout.cryptOffset)
		end := start + uint64(layout.cryptSize)
		sliceEnd := slice.offset + slice.size
		if start < slice.offset || end < start || start%page != 0 || end%page != 0 ||
			sliceEnd < slice.offset || end > sliceEnd {
			return nil, fmt.Errorf("SUPP universal encrypted range has invalid geometry")
		}
		id := [2]uint32{layout.cpuType, layout.cpuSubtype}
		if seen[id] {
			return nil, fmt.Errorf("SUPP universal image has duplicate architecture %#x/%#x", id[0], id[1])
		}
		seen[id] = true
		encrypted = append(encrypted, slice)
		lastEnd = max(lastEnd, end)
	}
	if len(encrypted) == 0 || uint64(len(s.records)) != lastEnd/page {
		return nil, fmt.Errorf("SUPP record count does not match universal encrypted ranges")
	}
	architectures := make([]supfArchitecture, 0, len(encrypted))
	for _, slice := range encrypted {
		layout := slice.layout
		start := (slice.offset + uint64(layout.cryptOffset)) / page
		end := start + uint64(layout.cryptSize)/page
		architectures = append(architectures, supfArchitecture{
			cpuType: layout.cpuType, cpuSubtype: layout.cpuSubtype, records: s.records[start:end],
		})
	}
	return architectures, nil
}

// selectImageKeyTable uses the architecture-indexed f-class when present.
// The older p-class has file-origin records. Universal p-class tables are
// mapped by absolute file page and must cover every encrypted slice exactly.
// A malformed selected class never triggers a retry with another class.
func selectImageKeyTable(files map[string]*zip.File, member string, slices []machoSlice) (string, supf, error) {
	return selectImageKeyTableWithCA(files, member, slices, nil)
}

func selectImageKeyTableWithCA(files map[string]*zip.File, member string, slices []machoSlice, authority *rsa.PublicKey) (string, supf, error) {
	base := path.Join(path.Dir(member), "SC_Info", path.Base(member))
	if _, present := files[base+".supf"]; present {
		return selectSUPF(files, member)
	}
	if _, present := files[base+".v5.supf"]; present {
		return selectSUPF(files, member)
	}
	names := [2]string{base + ".supp", base + ".v4.supp"}
	var tables [2]supp
	var present [2]bool
	for i, name := range names {
		f, exists := files[name]
		if !exists {
			continue
		}
		if f == nil {
			return "", supf{}, fmt.Errorf("invalid SUPP member %q", name)
		}
		data, err := zipBytes(f)
		if err != nil {
			return "", supf{}, err
		}
		tables[i], err = parseSUPPWithCA(data, authority)
		clear(data)
		if err != nil {
			return "", supf{}, fmt.Errorf("%s: %w", name, err)
		}
		expected := byte(1)
		if i == 1 {
			expected = 4
		}
		if tables[i].variant != expected {
			return "", supf{}, fmt.Errorf("SUPP %q has unexpected variant", name)
		}
		present[i] = true
	}
	if !present[0] && !present[1] {
		return "", supf{}, fmt.Errorf("encrypted Mach-O %q has no adjacent SUPF or SUPP", member)
	}
	if present[0] && present[1] {
		if len(tables[0].records) != len(tables[1].records) {
			return "", supf{}, fmt.Errorf("SUPP variants have different page counts")
		}
		for i := range tables[0].records {
			if !bytes.Equal(tables[0].records[i][:], tables[1].records[i][:]) {
				return "", supf{}, fmt.Errorf("SUPP variants have different page records")
			}
		}
		tables[1].SignatureSHA1 = tables[0].SignatureSHA1
		tables[1].HasSignatureSHA1 = true
	}
	chosen := 0
	if present[1] {
		chosen = 1
	}
	table := tables[chosen]
	architectures, err := table.architecturesForSlices(slices)
	if err != nil {
		return "", supf{}, err
	}
	selected := supf{variant: table.variant, architectures: architectures}
	if (len(slices) != 1 || slices[0].offset != 0) && table.HasSignatureSHA1 {
		selected.UniversalSignatureSHA1 = table.SignatureSHA1
		selected.HasUniversalSignatureSHA1 = true
	}
	return names[chosen], selected, nil
}
