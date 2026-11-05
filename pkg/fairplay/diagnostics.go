package fairplay

import (
	"archive/zip"
	"crypto/aes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type SINFDiagnostic struct {
	Error         string       `json:"error,omitempty"`
	Path          string       `json:"path,omitempty"`
	SHA256        string       `json:"sha256"`
	Bytes         int          `json:"bytes"`
	Selector      SINFSelector `json:"selector"`
	SelectorID    string       `json:"selector_id"`
	PrivateBytes  int          `json:"private_bytes"`
	RightsBytes   int          `json:"rights_bytes"`
	Atoms         []string     `json:"atoms"`
	CurrentLayout bool         `json:"current_layout"`
	LegacyMarkers bool         `json:"legacy_markers"`
}

type EnrollmentModelDiagnostic struct {
	Path                string        `json:"path"`
	SHA256              string        `json:"sha256"`
	Bytes               int           `json:"bytes"`
	Version             uint32        `json:"version"`
	ModelIdentitySHA256 string        `json:"model_identity_sha256"`
	Selector            *SINFSelector `json:"selector,omitempty"`
	SelectorID          string        `json:"selector_id,omitempty"`
}

type FairPlayDoctorReport struct {
	Schema                 string                       `json:"schema"`
	CreatedAt              string                       `json:"created_at"`
	Ready                  bool                         `json:"ready"`
	DecryptReady           bool                         `json:"decrypt_ready"`
	Host                   *FairPlayHostDiagnostic      `json:"host,omitempty"`
	Capture                *EnrollmentCaptureDiagnostic `json:"capture,omitempty"`
	CaptureVerified        bool                         `json:"capture_verified"`
	SINF                   []SINFDiagnostic             `json:"sinf,omitempty"`
	Models                 []EnrollmentModelDiagnostic  `json:"models,omitempty"`
	CompatibleModel        string                       `json:"compatible_model,omitempty"`
	CompatibleModelsBySINF map[string]string            `json:"compatible_models_by_sinf,omitempty"`
	CanonicalInput         *CanonicalEnrollmentInput    `json:"canonical_input,omitempty"`
	Checks                 map[string]bool              `json:"checks"`
	Errors                 []string                     `json:"errors,omitempty"`
	Warnings               []string                     `json:"warnings,omitempty"`
	NextActions            []string                     `json:"next_actions,omitempty"`
}

type EnrollmentCaptureDiagnostic struct {
	ProductVersion    string               `json:"product_version"`
	BuildVersion      string               `json:"build_version"`
	FairPlaydSHA256   string               `json:"fairplayd_sha256,omitempty"`
	EnrollmentSupport FairPlayBuildSupport `json:"enrollment_support"`
	SelectorID        string               `json:"selector_id"`
	Files             int                  `json:"files"`
	HasIPA            bool                 `json:"has_ipa"`
}

type FairPlayHostDiagnostic struct {
	ProductVersion     string               `json:"product_version"`
	BuildVersion       string               `json:"build_version"`
	FairPlaydSHA256    string               `json:"fairplayd_sha256"`
	EnrollmentSupport  FairPlayBuildSupport `json:"enrollment_support"`
	StateAccessible    bool                 `json:"state_accessible"`
	StateFiles         int                  `json:"state_files"`
	HardwareMACPresent bool                 `json:"hardware_iomac_present"`
}

func InspectLocalFairPlayHost() (FairPlayHostDiagnostic, error) {
	var result FairPlayHostDiagnostic
	if runtime.GOOS != "darwin" {
		return result, fmt.Errorf("local FairPlay host inspection requires macOS")
	}
	var err error
	result.ProductVersion, err = querySystemVersion("-productVersion")
	if err != nil {
		return result, err
	}
	result.BuildVersion, err = querySystemVersion("-buildVersion")
	if err != nil {
		return result, err
	}
	result.FairPlaydSHA256, _, err = arm64eMachOHash("/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/fairplayd")
	if err != nil {
		return result, err
	}
	support, _ := ResolveFairPlayBuildSupport(result.FairPlaydSHA256, result.BuildVersion)
	result.EnrollmentSupport = support
	entries, stateErr := os.ReadDir("/private/var/db/fpsd/SC Info")
	if stateErr == nil {
		result.StateAccessible = true
		for _, entry := range entries {
			if !entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
				result.StateFiles++
			}
		}
	}
	mac, macErr := ioregHardwareMAC("en0")
	if macErr == nil && len(mac) == 6 {
		result.HardwareMACPresent = true
		clear(mac)
	}
	return result, nil
}

func InspectSINF(data []byte) (SINFDiagnostic, error) {
	var result SINFDiagnostic
	digest := sha256.Sum256(data)
	result.SHA256 = hex.EncodeToString(digest[:])
	result.Bytes = len(data)
	fields, err := parseSINFFields(data)
	if err != nil {
		return result, err
	}
	selector, err := sinfSelector(data, fields)
	if err != nil {
		return result, err
	}
	result.Selector = selector
	result.SelectorID = selector.Identifier()
	var rights, private []byte
	for _, field := range fields {
		result.Atoms = append(result.Atoms, field.typ)
		if field.typ == "priv" {
			result.PrivateBytes = field.end - field.start
			private = data[field.start:field.end]
		}
		if field.typ == "righ" {
			rights = data[field.start:field.end]
			result.RightsBytes = len(rights)
		}
		if field.typ == "crdt" || field.typ == "asdt" {
			result.LegacyMarkers = true
		}
	}
	// Current Store enrollments can retain legacy crdt/asdt atoms. Detect the
	// layout from its structural rights/private relationship rather than two
	// pinned private-record sizes.
	if rightsErr := currentSINFRightsPayloadGeometry(rights); rightsErr == nil && len(private) == 360+len(rights) {
		trailerBytes := len(private) % aes.BlockSize
		result.CurrentLayout = trailerBytes == 0 || trailerBytes == 8
		for _, value := range private[len(private)-trailerBytes:] {
			result.CurrentLayout = result.CurrentLayout && value == 0
		}
	}
	return result, nil
}

func InspectEnrollmentModel(path string) (EnrollmentModelDiagnostic, error) {
	var result EnrollmentModelDiagnostic
	pack, err := readEnrollmentModel(path)
	if err != nil {
		return result, err
	}
	defer clear(pack)
	model, err := parseCurrentSINFModel(pack)
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(pack)
	result = EnrollmentModelDiagnostic{
		Path: path, SHA256: hex.EncodeToString(digest[:]), Bytes: len(pack), Version: model.version,
		ModelIdentitySHA256: hex.EncodeToString(model.modelIdentity[:]),
	}
	if model.hasSelector {
		selector := model.selector
		result.Selector = &selector
		result.SelectorID = selector.Identifier()
	}
	return result, nil
}

func inspectModelPath(path string) ([]EnrollmentModelDiagnostic, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		model, err := InspectEnrollmentModel(path)
		return []EnrollmentModelDiagnostic{model}, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("model directory must be mode 0700 or stricter")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var result []EnrollmentModelDiagnostic
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".bin") {
			continue
		}
		model, err := InspectEnrollmentModel(filepath.Join(path, entry.Name()))
		if err != nil {
			return nil, err
		}
		result = append(result, model)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("model directory contains no .bin models")
	}
	return result, nil
}

// A nil used set scans every license for diagnostics. A non-nil set limits
// readiness checks to licenses used by encrypted executables.
func inspectIPASINFs(ipaPath string, used map[string]bool) ([]SINFDiagnostic, error) {
	archive, err := zip.OpenReader(ipaPath)
	if err != nil {
		return nil, err
	}
	defer archive.Close()
	var result []SINFDiagnostic
	var failures []error
	for _, file := range archive.File {
		if used != nil {
			if !used[file.Name] {
				continue
			}
		} else if !(strings.Contains(file.Name, "/SC_Info/") || strings.HasPrefix(file.Name, "SC_Info/")) ||
			!strings.HasSuffix(strings.ToLower(file.Name), ".sinf") {
			continue
		}
		data, err := zipBytes(file)
		var value SINFDiagnostic
		if err == nil {
			value, err = InspectSINF(data)
		}
		value.Path = file.Name
		if err != nil {
			value.Error = err.Error()
			failures = append(failures, fmt.Errorf("inspect %s: %w", file.Name, err))
		}
		result = append(result, value)
	}
	if len(result) == 0 {
		failures = append(failures, fmt.Errorf("IPA contains no SINF files"))
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Path < result[right].Path })
	return result, errors.Join(failures...)
}

func readIPASINF(path, member string) ([]byte, error) {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer archive.Close()
	var selected *zip.File
	for _, file := range archive.File {
		if file.Name != member {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("IPA has duplicate SINF member %q", member)
		}
		selected = file
	}
	if selected == nil {
		return nil, fmt.Errorf("IPA SINF member %q is missing", member)
	}
	return zipBytes(selected)
}

func validatedModelForSINF(ipaPath, member, modelPath string,
	models []EnrollmentModelDiagnostic) (string, error) {
	sinf, err := readIPASINF(ipaPath, member)
	if err != nil {
		return "", err
	}
	defer clear(sinf)
	info, err := os.Stat(modelPath)
	if err != nil {
		return "", err
	}
	var material KeyMaterial
	if info.IsDir() {
		packs, readErr := readEnrollmentModelRegistry(modelPath)
		if readErr != nil {
			return "", readErr
		}
		defer clearModelPacks(packs)
		eligible := make([][]byte, 0, len(packs))
		for _, pack := range packs {
			eligible = append(eligible, pack)
		}
		material, err = ResolveLogicalKeyWithModels(sinf, eligible)
	} else {
		pack, readErr := readEnrollmentModel(modelPath)
		if readErr != nil {
			return "", readErr
		}
		defer clear(pack)
		material, err = ResolveLogicalKeyWithModel(sinf, pack)
	}
	if err != nil {
		return "", err
	}
	defer clear(material.LogicalKey[:])
	selectedHash, _ := material.Evidence["model_sha256"].(string)
	for _, model := range models {
		if model.SHA256 == selectedHash {
			return model.Path, nil
		}
	}
	return "", fmt.Errorf("validated enrollment model is missing from diagnostics")
}

func DoctorFairPlay(capturePath, ipaPath, modelPath string) FairPlayDoctorReport {
	report := FairPlayDoctorReport{
		Schema: "unfairplay-doctor-v1", CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Checks: make(map[string]bool),
	}
	var captureManifest *EnrollmentCaptureManifest
	if capturePath == "" {
		if host, err := InspectLocalFairPlayHost(); err == nil {
			report.Host = &host
			report.Checks["supported_enrollment_contract"] = host.EnrollmentSupport.Decrypt
			report.Checks["portable_semantic_recovery_available"] = host.EnrollmentSupport.Recovery
			report.Checks["verified_enrollment_contract"] = host.EnrollmentSupport.Decrypt
			if host.EnrollmentSupport.Recovery && !host.EnrollmentSupport.Decrypt {
				report.Checks["portable_semantic_validation_candidate"] = true
				report.Warnings = append(report.Warnings,
					"this fairplayd hash is not independently verified; collect a matching IPA and require complete recovery validation")
			}
			report.Checks["native_state_accessible"] = host.StateAccessible && host.StateFiles != 0
			report.Checks["hardware_iomac"] = host.HardwareMACPresent
		} else if ipaPath == "" && modelPath == "" {
			report.Errors = append(report.Errors, "host: "+err.Error())
		}
	}
	if capturePath != "" {
		capture, err := LoadEnrollmentCapture(capturePath, true)
		if err != nil {
			report.Errors = append(report.Errors, "capture: "+err.Error())
		} else {
			captureManifest = &capture
			report.Capture = &EnrollmentCaptureDiagnostic{
				ProductVersion:    capture.ProductVersion,
				BuildVersion:      capture.BuildVersion,
				FairPlaydSHA256:   capture.FairPlayd.SHA256,
				EnrollmentSupport: capture.FairPlay,
				SelectorID:        capture.App.SelectorID,
				Files:             len(capture.Files),
				HasIPA:            capture.IPA != nil,
			}
			report.CaptureVerified = true
			report.Checks["capture_integrity"] = true
			report.Checks["supported_enrollment_contract"] = capture.FairPlay.Decrypt
			report.Checks["portable_semantic_recovery_available"] = capture.FairPlay.Recovery
			report.Checks["verified_enrollment_contract"] = capture.FairPlay.Decrypt
			canonical, normalizeErr := NormalizeEnrollmentCapture(capturePath, capture)
			if normalizeErr != nil {
				report.Errors = append(report.Errors, "canonical input: "+normalizeErr.Error())
			} else {
				report.CanonicalInput = &canonical
				report.Checks["canonical_enrollment_input"] = canonical.RecoveryReady
			}
			if capture.FairPlay.Recovery && !capture.FairPlay.Decrypt {
				report.Checks["portable_semantic_validation_candidate"] = true
				report.Warnings = append(report.Warnings,
					"this fairplayd hash is not independently verified; recovery will use the portable semantic evaluator and promote a model only after complete SINF and IPA validation")
			}
			if ipaPath == "" && capture.IPA != nil {
				resolved, resolveErr := captureFilePath(capturePath, capture.IPA.Path)
				if resolveErr != nil {
					report.Errors = append(report.Errors, "capture IPA: "+resolveErr.Error())
				} else {
					ipaPath = resolved
				}
			}
		}
	}
	if ipaPath != "" {
		inventory, archive, inventoryErr := openIPAInventory(ipaPath)
		if archive != nil {
			_ = archive.Close()
		}
		var used map[string]bool
		if inventoryErr != nil {
			report.Errors = append(report.Errors, "ipa inventory: "+inventoryErr.Error())
		} else {
			report.Checks["ipa_inventory"] = true
			used = make(map[string]bool)
			for _, image := range inventory.images {
				used[image.sinfMember] = true
			}
		}
		sinfs, err := inspectIPASINFs(ipaPath, used)
		report.SINF = sinfs
		if err != nil {
			report.Errors = append(report.Errors, "ipa: "+err.Error())
		}
		if len(sinfs) > 0 {
			report.Checks["ipa_sinf"] = err == nil
			current := err == nil
			for _, value := range sinfs {
				current = current && value.CurrentLayout
			}
			report.Checks["current_sinf_layout"] = current
			if !current {
				report.Warnings = append(report.Warnings, "one or more inspected SINF files use an unsupported or legacy layout")
			}
		}
	}
	if captureManifest != nil || len(report.SINF) != 0 {
		report.Warnings = append(report.Warnings, "SINF geometry cannot prove account age; untested migrated or legacy enrollment layouts still fail closed")
	}
	if modelPath != "" {
		models, err := inspectModelPath(modelPath)
		if err != nil {
			report.Errors = append(report.Errors, "model: "+err.Error())
		} else {
			report.Models = models
			report.Checks["model_valid"] = true
		}
	}
	if len(report.SINF) != 0 && len(report.Models) != 0 {
		allSelectors, allValidated := true, true
		report.CompatibleModelsBySINF = make(map[string]string)
		for _, sinf := range report.SINF {
			matched := false
			for _, model := range report.Models {
				if model.SelectorID == sinf.SelectorID || model.SelectorID == "" && len(report.Models) == 1 {
					matched = true
				}
			}
			if !matched {
				allSelectors = false
				allValidated = false
				report.Errors = append(report.Errors, "no enrollment model matches SINF "+sinf.Path)
				continue
			}
			selected, err := validatedModelForSINF(ipaPath, sinf.Path,
				modelPath, report.Models)
			if err != nil {
				allValidated = false
				report.Errors = append(report.Errors, "model validation for "+sinf.Path+": "+err.Error())
			} else {
				report.CompatibleModelsBySINF[sinf.Path] = selected
				if report.CompatibleModel == "" {
					report.CompatibleModel = selected
				} else if report.CompatibleModel != selected {
					report.CompatibleModel = modelPath
				}
			}
		}
		if !allValidated {
			report.CompatibleModel = ""
		}
		report.Checks["selector_match"] = allSelectors
		report.Checks["sinf_model_validation"] = allValidated
	}
	if captureManifest != nil && len(report.SINF) != 0 {
		matched := false
		for _, value := range report.SINF {
			matched = matched || value.Selector == captureManifest.App.Selector
		}
		report.Checks["capture_selector_match"] = matched
		if !matched {
			report.Errors = append(report.Errors, "capture selector does not match the IPA")
		}
	}
	if captureManifest == nil {
		if report.Host != nil && !report.Host.StateAccessible {
			report.NextActions = append(report.NextActions, "rerun collection with permission to read /private/var/db/fpsd")
		}
		report.NextActions = append(report.NextActions, "collect native enrollment with unfairplay collect")
	} else if modelPath == "" {
		report.NextActions = append(report.NextActions, "recover fairplay-enrollment.bin with unfairplay recover")
	}
	if modelPath != "" && report.CompatibleModel != "" {
		report.NextActions = append(report.NextActions, "run unfairplay decrypt with the validated model")
	}
	if len(report.SINF) != 0 || captureManifest != nil || modelPath != "" {
		report.Ready = len(report.Errors) == 0 && report.Checks["current_sinf_layout"] &&
			(captureManifest == nil || report.Checks["capture_integrity"] && report.Checks["portable_semantic_recovery_available"] && report.Checks["capture_selector_match"] && report.Checks["canonical_enrollment_input"]) &&
			(modelPath == "" || report.Checks["sinf_model_validation"])
	} else if report.Host != nil {
		report.Ready = report.Checks["portable_semantic_recovery_available"] && report.Checks["native_state_accessible"] && report.Checks["hardware_iomac"]
	}
	report.DecryptReady = modelPath != "" && report.Ready && report.CompatibleModel != ""
	return report
}

func WriteDoctorReport(path string, report FairPlayDoctorReport) error {
	if path == "" {
		return nil
	}
	return writePrivateJSON(path, report)
}

func MarshalDoctorReport(report FairPlayDoctorReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}
