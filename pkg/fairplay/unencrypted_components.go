package fairplay

import (
	"archive/zip"
	"fmt"
	"strings"
)

// Inert means every parsed slice has both cryptid and cryptsize zero.
// No envelope belonging to these routes is consumed or asserted authenticated.
func unencryptedLicenseRoutes(files map[string]*zip.File) (map[string]bool, error) {
	result := map[string]bool{}
	for n, v := range files {
		if v.FileInfo().IsDir() {
			continue
		}
		probe, e := readMachOProbe(v)
		if e != nil {
			return nil, e
		}
		if len(probe) < 4 {
			continue
		}
		if !isFatMachO(probe) && !(probe[0] == 0xce || probe[0] == 0xcf) && !isKnownUnsupportedMachO(probe) {
			continue
		}
		// Full magic check before treating arbitrary resources as Mach-O.
		if !isFatMachO(probe) && !(probe[0] == 0xce && probe[1] == 0xfa && probe[2] == 0xed && probe[3] == 0xfe) && !(probe[0] == 0xcf && probe[1] == 0xfa && probe[2] == 0xed && probe[3] == 0xfe) {
			if isKnownUnsupportedMachO(probe) {
				return nil, fmt.Errorf("unsupported Mach-O")
			}
			continue
		}
		b, e := zipBytes(v)
		if e != nil {
			return nil, e
		}
		ss, e := parseMachOSlices(b, uint64(len(b)))
		if e != nil {
			return nil, e
		}
		inert := len(ss) > 0
		for _, s := range ss {
			if s.layout.cryptSize != 0 || s.layout.cryptID != 0 {
				inert = false
			}
		}
		if inert {
			result[adjacentSINF(n)] = true
		}
	}
	return result, nil
}
func unusedComponentEnvelope(n string, inert map[string]bool) bool {
	for _, suffix := range []string{".v5.supf", ".v4.supp", ".supf", ".supp"} {
		if strings.HasSuffix(n, suffix) {
			return inert[strings.TrimSuffix(n, suffix)+".sinf"]
		}
	}
	return false
}

// Only whole nested bundles containing no encrypted image qualify for raw copy.
func UnencryptedBundles(input string) ([]string, error) {
	z, e := zip.OpenReader(input)
	if e != nil {
		return nil, e
	}
	defer z.Close()
	files := map[string]*zip.File{}
	for _, v := range z.File {
		if files[v.Name] != nil {
			return nil, fmt.Errorf("duplicate")
		}
		files[v.Name] = v
	}
	inert, e := unencryptedLicenseRoutes(files)
	if e != nil {
		return nil, e
	}
	candidates := map[string]bool{}
	for n := range files {
		parts := strings.Split(n, "/")
		for j, part := range parts {
			if j > 1 && (strings.HasSuffix(part, ".app") || strings.HasSuffix(part, ".framework") || strings.HasSuffix(part, ".appex")) {
				candidates[strings.Join(parts[:j+1], "/")+"/"] = true
			}
		}
	}
	out := []string{}
	for prefix := range candidates {
		seen := false
		valid := true
		for n, v := range files {
			if !strings.HasPrefix(n, prefix) || v.FileInfo().IsDir() {
				continue
			}
			probe, e := readMachOProbe(v)
			if e != nil {
				return nil, e
			}
			if len(probe) < 4 {
				continue
			}
			if !isFatMachO(probe) && !(probe[0] == 0xce && probe[1] == 0xfa && probe[2] == 0xed && probe[3] == 0xfe) && !(probe[0] == 0xcf && probe[1] == 0xfa && probe[2] == 0xed && probe[3] == 0xfe) {
				continue
			}
			seen = true
			if !inert[adjacentSINF(n)] {
				valid = false
			}
		}
		if seen && valid {
			out = append(out, prefix)
		}
	}
	return out, nil
}
