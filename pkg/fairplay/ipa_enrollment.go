package fairplay

import (
	"archive/zip"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// IPAEnrollmentInputs contains one deterministic SINF and every page-key
// envelope in the selected classes. All encrypted images must share a selector.
// The full IPA must still decrypt and validate before its model is installed.
type IPAEnrollmentInputs struct {
	Selector SINFSelector
	Files    map[string][]byte
}

const maximumEnrollmentLicenseBytes = 16 << 20

func (input *IPAEnrollmentInputs) Clear() {
	for name, data := range input.Files {
		clear(data)
		delete(input.Files, name)
	}
}

func boundedEnrollmentMember(file *zip.File) ([]byte, error) {
	if file == nil || file.UncompressedSize64 > maximumEnrollmentLicenseBytes {
		return nil, fmt.Errorf("IPA enrollment license exceeds size limit")
	}
	r, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, maximumEnrollmentLicenseBytes+1))
	if err != nil || len(data) > maximumEnrollmentLicenseBytes {
		clear(data)
		return nil, fmt.Errorf("could not read bounded IPA enrollment license")
	}
	return data, nil
}

func ReadIPAEnrollmentInputs(name string) (result IPAEnrollmentInputs, err error) {
	result.Files = make(map[string][]byte)
	defer func() {
		if err != nil {
			result.Clear()
		}
	}()
	// Inventory parses manifests and key tables, so apply the license bound
	// before that parser allocates their uncompressed contents.
	preflight, err := zip.OpenReader(name)
	if err != nil {
		return result, err
	}
	for _, file := range preflight.File {
		if strings.HasSuffix(file.Name, ".sinf") || strings.HasSuffix(file.Name, ".supf") || strings.HasSuffix(file.Name, ".supp") || strings.HasSuffix(file.Name, "/SC_Info/Manifest.plist") {
			if file.UncompressedSize64 > maximumEnrollmentLicenseBytes {
				preflight.Close()
				return result, fmt.Errorf("IPA enrollment license exceeds size limit")
			}
		}
	}
	if err := preflight.Close(); err != nil {
		return result, err
	}
	inventory, archive, err := openIPAInventory(name)
	if err != nil {
		return result, err
	}
	defer archive.Close()
	files := make(map[string]*zip.File, len(archive.File))
	for _, f := range archive.File {
		files[f.Name] = f
	}
	sinfs := make(map[string]bool)
	keyfiles := make(map[string]bool)
	for _, image := range inventory.images {
		sinfs[image.sinfMember] = true
		base := path.Join(path.Dir(image.member), "SC_Info", path.Base(image.member))
		suffixes := []string{".supf", ".v5.supf"}
		if strings.HasSuffix(image.supfMember, ".supp") {
			suffixes = []string{".supp", ".v4.supp"}
		}
		for _, suffix := range suffixes {
			if files[base+suffix] != nil {
				keyfiles[base+suffix] = true
			}
		}
	}
	names := make([]string, 0, len(sinfs))
	for name := range sinfs {
		names = append(names, name)
	}
	sort.Strings(names)
	for i, name := range names {
		data, readErr := boundedEnrollmentMember(files[name])
		if readErr != nil {
			return result, readErr
		}
		selector, parseErr := ParseSINFSelector(data)
		if parseErr != nil {
			clear(data)
			return result, parseErr
		}
		if i == 0 {
			result.Selector = selector
			result.Files["selected.sinf"] = data
		} else {
			clear(data)
			if selector != result.Selector {
				return result, fmt.Errorf("snapshot setup requires one SINF selector across all encrypted images; use separate validated models for multi-selector IPAs")
			}
		}
	}
	// Selection is lexical and never retried if authentication fails. Every
	// remaining SINF is checked using that model by complete IPA validation.
	for name := range keyfiles {
		data, readErr := boundedEnrollmentMember(files[name])
		if readErr != nil {
			return result, readErr
		}
		result.Files[name] = data
	}
	return result, nil
}
