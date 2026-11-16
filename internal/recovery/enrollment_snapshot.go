package recovery

import (
	"context"
	"fmt"
	"strings"

	"github.com/DrWhax/unfairplay/pkg/fairplay"
)

// ValidateEnrollmentSnapshot authenticates and decodes the container without
// selecting an account. Success is not SINF or end-to-end IPA validation.
func ValidateEnrollmentSnapshot(ctx context.Context, snapshot fairplay.EnrollmentSnapshot) error {
	recoveryMu.Lock()
	defer recoveryMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	registries, _, _, _, err := deriveCurrentSelectionRegistryCandidatesWithEvidence(map[string][]byte{"SC Info.sidb": snapshot.SIDB}, snapshot.Hardware[:])
	clearDecodedSIDBRegistryCandidates(registries)
	if err != nil {
		return err
	}
	return ctx.Err()
}

// RecoverEnrollmentSnapshot borrows the inputs for this call. It derives one
// selector-bound candidate; the caller must validate the entire IPA before
// publishing it as a reusable model.
func RecoverEnrollmentSnapshot(ctx context.Context, snapshot fairplay.EnrollmentSnapshot, licenses fairplay.IPAEnrollmentInputs, progress func(Progress)) (Result, error) {
	recoveryMu.Lock()
	defer recoveryMu.Unlock()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	inputs, err := snapshotRecoveryInputs(snapshot, licenses)
	if err != nil {
		return Result{}, err
	}
	return recoverCurrentInputs(ctx, inputs, progress, nil)
}

func snapshotRecoveryInputs(snapshot fairplay.EnrollmentSnapshot, licenses fairplay.IPAEnrollmentInputs) (*currentRecoveryInputs, error) {
	files := make(map[string][]byte, len(licenses.Files)+1)
	sinfs := 0
	for name, data := range licenses.Files {
		if !isCurrentRecoveryFile(name) {
			return nil, fmt.Errorf("invalid IPA recovery input")
		}
		// IPA inputs may contain only licenses, never another SIDB container.
		if strings.HasSuffix(name, "SC Info.sidb") {
			return nil, fmt.Errorf("IPA cannot supply enrollment state")
		}
		if strings.HasSuffix(name, ".sinf") {
			sinfs++
			selector, err := fairplay.ParseSINFSelector(data)
			if err != nil {
				return nil, err
			}
			if selector != licenses.Selector {
				return nil, fmt.Errorf("IPA recovery selector does not match selected SINF")
			}
		}
		files[name] = data
	}
	if sinfs != 1 {
		return nil, fmt.Errorf("IPA recovery requires exactly one selected SINF")
	}
	files["SC Info.sidb"] = snapshot.SIDB
	return &currentRecoveryInputs{files: files, hardware: snapshot.Hardware[:]}, nil
}
