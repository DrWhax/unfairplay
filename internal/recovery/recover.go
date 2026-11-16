package recovery

import (
	"context"
	"crypto/rsa"
	"fmt"
	"os"
	"sync"
)

// Progress reports bounded, non-secret recovery work. Completed and Total are
// candidate comparisons, not bytes or key material.
type Progress struct {
	Phase              string
	Completed          uint64
	Total              uint64
	RegistryCandidates int
	RecordCandidates   int
	WindowCandidates   int
}

// Options describes the private runtime inputs used to derive one
// selector-bound enrollment model. FileMappings use SUFFIX=FILE syntax.
type Options struct {
	FileMappings []string
	HardwarePath string
	Context      context.Context
	Progress     func(Progress)
}

// LayoutEvidence records the one deterministic SIDB and SINF route that
// produced the authenticated model. It contains geometry and identifiers, not
// SIDB bytes, keys, hardware material, or decrypted license contents.
type LayoutEvidence struct {
	ContainerBytes        int    `json:"container_bytes"`
	CodecBytes            int    `json:"codec_bytes"`
	PayloadBytes          int    `json:"payload_bytes"`
	SourceBytes           int    `json:"source_bytes"`
	SelectorModulus       int    `json:"selector_modulus"`
	SelectedSlot          int    `json:"selected_slot"`
	RootCursor            int    `json:"root_cursor"`
	RootLength            int    `json:"root_length"`
	RootChildCount        int    `json:"root_child_count"`
	TreeNodes             int    `json:"tree_nodes"`
	RegistryRecords       int    `json:"registry_records"`
	RootVersion           uint32 `json:"root_version"`
	AccountVersion        uint32 `json:"account_version"`
	TypeCursor            int    `json:"type_cursor"`
	TypeLength            int    `json:"type_length"`
	SignCursor            int    `json:"sign_cursor"`
	SignLength            int    `json:"sign_length"`
	ValueCursor           int    `json:"value_cursor"`
	ValueLength           int    `json:"value_length"`
	SelectedRecordIndex   int    `json:"selected_record_index"`
	SelectedPayloadOffset int    `json:"selected_payload_offset"`
	SelectedWindowOffset  int    `json:"selected_window_offset"`
	SINFSelector          string `json:"sinf_selector"`
}

// Result is the output of one bounded enrollment recovery.
type Result struct {
	EnrollmentModel           []byte
	StateSHA256               string
	Iterations                int
	DecodedRegistryCandidates int
	Layout                    LayoutEvidence
}

var recoveryMu sync.Mutex

func readPrivateInput(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("recovery input must be a mode-0600 regular file: %s", path)
	}
	return os.ReadFile(path)
}

// Recover derives a selector-bound enrollment model from structurally parsed
// SIDB, SINF, SUPF, and hardware inputs. Native code and the captured
// executable are not part of the production recovery path.
func Recover(options Options) (Result, error) {
	recoveryMu.Lock()
	defer recoveryMu.Unlock()

	if len(options.FileMappings) == 0 {
		return Result{}, fmt.Errorf("recovery requires captured FairPlay files")
	}
	if options.HardwarePath == "" {
		return Result{}, fmt.Errorf("recovery requires a hardware identity file")
	}
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if options.Progress != nil {
		options.Progress(Progress{Phase: "load-inputs"})
	}
	inputs, err := loadCurrentRecoveryInputs(options.FileMappings, options.HardwarePath)
	if err != nil {
		return Result{}, err
	}
	defer inputs.clear()
	return recoverCurrentInputs(ctx, inputs, options.Progress, nil)
}

// An authority override is available only to package-local synthetic tests.
// Every public recovery entry point uses the pinned authority.
func recoverCurrentInputs(ctx context.Context, inputs *currentRecoveryInputs, progress func(Progress), authority *rsa.PublicKey) (Result, error) {
	if authority == nil {
		authority = fairPlayCAPublicKey()
	}
	if _, err := validateCurrentSUPFFilesWithCA(inputs.files, authority); err != nil {
		return Result{}, err
	}
	if progress != nil {
		progress(Progress{Phase: "decode-sidb"})
	}
	registries, digest, iterations, layout, err := deriveCurrentSelectionRegistryCandidatesWithEvidence(inputs.files, inputs.hardware)
	if err != nil {
		return Result{}, err
	}
	pack, route, err := currentEnrollmentPackWithContextEvidence(ctx, inputs.files, registries, inputs.hardware, progress)
	if err != nil {
		clearDecodedSIDBRegistryCandidates(registries)
		return Result{}, err
	}
	layout.RootVersion = route.RootVersion
	layout.AccountVersion = route.AccountVersion
	layout.TypeCursor, layout.TypeLength = route.TypeCursor, route.TypeLength
	layout.SignCursor, layout.SignLength = route.SignCursor, route.SignLength
	layout.ValueCursor, layout.ValueLength = route.ValueCursor, route.ValueLength
	layout.SelectedRecordIndex = route.SelectedRecordIndex
	layout.SelectedPayloadOffset = route.SelectedPayloadOffset
	layout.SelectedWindowOffset = route.SelectedWindowOffset
	layout.SINFSelector = route.SINFSelector
	clearDecodedSIDBRegistryCandidates(registries)
	return Result{
		EnrollmentModel: pack, StateSHA256: digest, Iterations: iterations,
		DecodedRegistryCandidates: len(registries), Layout: layout,
	}, nil
}
