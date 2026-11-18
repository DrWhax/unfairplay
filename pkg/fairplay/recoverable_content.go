package fairplay

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/DrWhax/unfairplay/internal/scinfo"
	"howett.net/plist"
)

// RestoreRecoverableContent restores encrypted ranges using one application key.
// It never retries a key class and requires signed envelopes and complete hashes.
func RestoreRecoverableContent(input, output string, appkey, sinf []byte) (err error) {
	if len(appkey) != 16 {
		return fmt.Errorf("expected one 16-byte content key")
	}
	var inner [16]byte
	copy(inner[:], appkey)
	logical := logicalFromInnerKey(inner)
	defer clear(inner[:])
	defer clear(logical[:])
	deriver := newPageKeyDeriver(appMaskFromLogicalKey(logical))
	z, e := zip.OpenReader(input)
	if e != nil {
		return e
	}
	defer z.Close()
	files := map[string]*zip.File{}
	for _, v := range z.File {
		if _, ok := files[v.Name]; ok {
			return fmt.Errorf("duplicate member")
		}
		if strings.HasPrefix(v.Name, "/") || strings.Contains(v.Name, "\\") {
			return fmt.Errorf("unsafe name")
		}
		for _, s := range strings.Split(v.Name, "/") {
			if s == ".." {
				return fmt.Errorf("unsafe name")
			}
		}
		if v.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink")
		}
		files[v.Name] = v
	}
	inert, e := unencryptedLicenseRoutes(files)
	if e != nil {
		return e
	}
	// Authenticate consumed image envelopes; inert image files are opaque copies.
	// Authenticate every retained page-key envelope, including the native class
	// that is not selected by the offline page decoder.
	for n, v := range files {
		if unusedComponentEnvelope(n, inert) {
			continue
		}
		if strings.HasSuffix(n, ".supf") || strings.HasSuffix(n, ".supp") {
			b, e := zipBytes(v)
			if e != nil {
				return e
			}
			if strings.HasSuffix(n, ".supf") {
				if len(b) == 0 && !strings.HasSuffix(n, ".v5.supf") {
					companion := files[strings.TrimSuffix(n, ".supf")+".v5.supf"]
					if companion == nil {
						return fmt.Errorf("empty legacy SUPF requires v5 companion")
					}
					other, e := zipBytes(companion)
					if e != nil {
						return e
					}
					if e = verifyRecoverySUPF(other); e != nil {
						return e
					}
					continue
				}
				if e = verifyRecoverySUPF(b); e != nil {
					return e
				}
			} else {
				if e = verifyRecoverySUPP(b); e != nil {
					return e
				}
			}
		}
	}
	changes := map[string][]byte{}
	licensePaths := map[string]bool{}
	count := 0
	for _, v := range z.File {
		if v.FileInfo().IsDir() {
			continue
		}
		probe, e := readMachOProbe(v)
		if e != nil {
			return e
		}
		if len(probe) < 4 {
			continue
		}
		magic := binary.LittleEndian.Uint32(probe)
		if magic != mhMagic32 && magic != mhMagic64 && !isFatMachO(probe) {
			if isKnownUnsupportedMachO(probe) {
				return fmt.Errorf("unsupported Mach-O")
			}
			continue
		}
		data, e := zipBytes(v)
		if e != nil {
			return e
		}
		slices, e := parseMachOSlices(data, uint64(len(data)))
		if e != nil {
			return e
		}
		route := adjacentSINF(v.Name)
		hasPageTable := hasRecoveryPageTable(files, route)
		selected := false
		// Bounds are validated by reparsing the restored encryption declaration,
		// before touching any data range. No guessed offsets or page counts.
		for _, s := range slices {
			l := s.layout
			if l.cryptID != 0 {
				return fmt.Errorf("not decrypted input")
			}
			if l.cryptSize == 0 {
				continue
			}
			if !hasPageTable {
				// Some unencrypted binaries retain LC_ENCRYPTION_INFO and a
				// nonzero range. Accept them unchanged only when the ordinary
				// CodeDirectory hashes already match the entire range.
				part := data[s.offset : s.offset+s.size]
				if e := verifyUnencryptedRecoveryRange(part, l); e != nil {
					return fmt.Errorf("%q has no adjacent SUPF or SUPP: %w", v.Name, e)
				}
				continue
			}
			if l.cryptIDOffset <= 0 {
				return fmt.Errorf("missing encryption command")
			}
			binary.LittleEndian.PutUint32(data[s.offset+uint64(l.cryptIDOffset):], 1)
			selected = true
		}
		if !selected {
			inert[route] = true
			continue
		}
		slices, e = parseMachOSlices(data, uint64(len(data)))
		if e != nil {
			return e
		}
		name, table, e := selectImageKeyTable(files, v.Name, slices)
		if e != nil {
			return e
		}
		envelope, e := zipBytes(files[name])
		if e != nil {
			return e
		}
		if strings.HasSuffix(name, ".supf") {
			if e = verifyRecoverySUPF(envelope); e != nil {
				return e
			}
		}
		if e = table.ValidateUniversalSignatureBinding(data, slices); e != nil {
			return e
		}
		for _, s := range slices {
			l := s.layout
			if l.cryptID == 0 {
				continue
			}
			part := data[s.offset : s.offset+s.size]
			binary.LittleEndian.PutUint32(part[l.cryptIDOffset:], 0)
			audits, e := auditPreEncryptionCodeDirectories(part, l)
			if e != nil || len(audits) == 0 {
				return fmt.Errorf("missing or invalid plaintext coverage")
			}
			for _, a := range audits {
				if a.MatchedSlots != a.SlotCount {
					return fmt.Errorf("plaintext mismatch")
				}
			}
			if e = table.ValidateSignatureBinding(part, l); e != nil {
				return e
			}
			records, e := table.recordsFor(l.cpuType, l.cpuSubtype)
			if e != nil {
				return e
			}
			before := bytes.Clone(part)
			keys, e := cryptPagesInPlace(part, encryptedImage{member: v.Name, layout: l, sliceOffset: s.offset}, records, deriver, true)
			clear(keys)
			if e != nil {
				return e
			}
			binary.LittleEndian.PutUint32(part[l.cryptIDOffset:], 1)
			a, b, id := int(l.cryptOffset), int(l.cryptOffset+l.cryptSize), l.cryptIDOffset
			if !bytes.Equal(before[:id], part[:id]) || !bytes.Equal(before[id+4:a], part[id+4:a]) || !bytes.Equal(before[b:], part[b:]) {
				return fmt.Errorf("mutation escaped range")
			}
			clear(before)
			audits, e = auditCodeDirectories(part, l)
			if e != nil || len(audits) == 0 {
				return fmt.Errorf("missing ciphertext hash coverage")
			}
			for _, a := range audits {
				if a.MatchedSlots != a.SlotCount {
					return fmt.Errorf("ciphertext mismatch")
				}
			}
			count++
		}
		changes[v.Name] = data
		licensePaths[route] = true
	}
	if count == 0 {
		return fmt.Errorf("no encrypted ranges to restore")
	}
	// Use the original signed-resource manifest to retain exact license routes.
	manifests := 0
	for n, v := range files {
		if !strings.HasSuffix(n, "/SC_Info/Manifest.plist") {
			continue
		}
		manifests++
		blob, e := zipBytes(v)
		if e != nil {
			return e
		}
		var manifest struct {
			Sources []string `plist:"SinfPaths"`
			Targets []string `plist:"SinfReplicationPaths"`
		}
		if _, e = plist.Unmarshal(blob, &manifest); e != nil {
			return e
		}
		if len(manifest.Sources) != 1 {
			return fmt.Errorf("one source license route required")
		}
		root := path.Dir(path.Dir(n))
		for _, rel := range append(manifest.Sources, manifest.Targets...) {
			if path.IsAbs(rel) || strings.Contains(rel, "\\") || path.Clean(rel) != rel || rel == ".." || strings.HasPrefix(rel, "../") || !strings.HasSuffix(rel, ".sinf") {
				return fmt.Errorf("invalid SINF route")
			}
			target := path.Join(root, rel)
			if !inert[target] {
				licensePaths[target] = true
			}
		}
	}
	if manifests != 1 {
		return fmt.Errorf("one app manifest required for this minimal profile")
	}

	for n := range licensePaths {
		if files[n] != nil {
			return fmt.Errorf("original SINF not allowed")
		}
		changes[n] = sinf
	}
	f, e := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer func() {
		f.Close()
		if err != nil {
			os.Remove(output)
		}
	}()
	w := zip.NewWriter(f)
	done := map[string]bool{}
	for _, v := range z.File {
		if strings.HasSuffix(v.Name, ".sinf-recovery") {
			continue
		}
		if strings.HasSuffix(v.Name, ".sinf") {
			return fmt.Errorf("source SINF forbidden")
		}
		if b, ok := changes[v.Name]; ok {
			h := v.FileHeader
			out, e := w.CreateHeader(&h)
			if e != nil {
				return e
			}
			if _, e = out.Write(b); e != nil {
				return e
			}
			done[v.Name] = true
		} else if e = w.Copy(v); e != nil {
			return e
		}
	}
	names := []string{}
	for n := range changes {
		if !done[n] {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		h := zip.FileHeader{Name: n, Method: zip.Deflate}
		h.SetMode(0600)
		out, e := w.CreateHeader(&h)
		if e != nil {
			return e
		}
		if _, e = out.Write(changes[n]); e != nil {
			return e
		}
	}
	if e = w.Close(); e != nil {
		return e
	}
	return f.Close()
}

func verifyRecoverySUPF(b []byte) error {
	if len(b) < 12 || (b[0] != 3 && b[0] != 5) {
		return fmt.Errorf("SUPF envelope version")
	}
	end := 8 + int(binary.BigEndian.Uint32(b[4:8]))
	if end < 12 || end > len(b)-4 {
		return fmt.Errorf("SUPF prefix extent")
	}
	cn := int(binary.BigEndian.Uint32(b[end:]))
	cs := end + 4
	if cn < 1 || cn > len(b)-cs-4 {
		return fmt.Errorf("SUPF certificate extent")
	}
	ce := cs + cn
	sn := int(binary.BigEndian.Uint32(b[ce:]))
	ss := ce + 4
	if sn != len(b)-ss {
		return fmt.Errorf("SUPF signature extent")
	}
	return scinfo.VerifyEnvelope(b[0], b[:end], b[cs:ce], b[ss:], nil)
}

// Non-encrypted images can carry signed empty p-tables; selected encryption
// still goes through parseSUPPWithCA and its nonempty geometry requirements.
func verifyRecoverySUPP(b []byte) error {
	if len(b) < 8 || (b[0] != 1 && b[0] != 4) {
		return fmt.Errorf("SUPP envelope version")
	}
	cursor := 4
	if b[0] == 1 {
		cursor += 20
	}
	if len(b) < cursor+4 {
		return fmt.Errorf("SUPP bounds")
	}
	pages := uint64(binary.BigEndian.Uint32(b[cursor:]))
	cursor += 4
	if pages > uint64(len(b)-cursor)/32 {
		return fmt.Errorf("SUPP pages extent")
	}
	end := cursor + int(pages)*32
	if len(b)-end < 4+128 {
		return fmt.Errorf("SUPP certificate extent")
	}
	cs := end + 4
	cn := int(binary.BigEndian.Uint32(b[end:]))
	if cn < 1 || cn != len(b)-cs-128 {
		return fmt.Errorf("SUPP certificate length")
	}
	return scinfo.VerifyEnvelope(b[0], b[:end], b[cs:cs+cn], b[cs+cn:], nil)
}

func hasRecoveryPageTable(files map[string]*zip.File, sinfRoute string) bool {
	base := strings.TrimSuffix(sinfRoute, ".sinf")
	for _, suffix := range []string{".supf", ".v5.supf", ".supp", ".v4.supp"} {
		if _, present := files[base+suffix]; present {
			return true
		}
	}
	return false
}

func verifyUnencryptedRecoveryRange(part []byte, layout machoLayout) error {
	audits, err := auditCodeDirectories(part, layout)
	if err != nil {
		return err
	}
	if len(audits) == 0 {
		return fmt.Errorf("missing ordinary CodeDirectory coverage")
	}
	for _, audit := range audits {
		if audit.SlotCount == 0 || audit.MatchedSlots != audit.SlotCount {
			return fmt.Errorf("ordinary CodeDirectory hashes do not match the unchanged range")
		}
	}
	return nil
}
