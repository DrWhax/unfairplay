package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DrWhax/unfairplay/internal/recovery"
	"github.com/DrWhax/unfairplay/pkg/fairplay"
)

// RecoverOptions configures Recover.
type RecoverOptions struct {
	Capture string
	Output  string
	// Progress, when set, receives one status line per recovery step.
	Progress func(string)
}

// Result is the JSON-ready summary of a run and the path of the recovered model.
type Result struct {
	Summary   map[string]any
	ModelPath string
}

func (options RecoverOptions) report(format string, args ...any) {
	if options.Progress != nil {
		options.Progress(fmt.Sprintf(format, args...))
	}
}

func writePrivateFile(path string, value []byte) (returnErr error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".unfairplay-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	published := false
	defer func() {
		_ = temporary.Close()
		if returnErr != nil {
			_ = os.Remove(temporaryPath)
			if published {
				_ = os.Remove(path)
			}
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(value); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return err
	}
	published = true
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return os.Remove(temporaryPath)
}

// Recover derives a private enrollment model from a capture and validates it
// against the capture's IPA.
func Recover(ctx context.Context, options RecoverOptions) (Result, error) {
	var outcome Result
	manifest, err := fairplay.LoadEnrollmentCapture(options.Capture, true)
	if err != nil {
		return outcome, fmt.Errorf("validate capture: %w", err)
	}
	if manifest.IPA == nil {
		return outcome, errors.New("capture has no matching personalized IPA")
	}
	validationSource := manifest.IPASource
	if validationSource == "" {
		validationSource = "provided"
	}
	canonical, err := fairplay.NormalizeEnrollmentCapture(options.Capture, manifest)
	if err != nil {
		return outcome, fmt.Errorf("normalize capture: %w", err)
	}
	if !canonical.RecoveryReady {
		return outcome, errors.New("canonical enrollment input is not recovery-ready")
	}
	referenceSource := "typed-go"
	if err := os.Mkdir(options.Output, 0o700); err != nil {
		return outcome, err
	}
	canonicalDocument, err := fairplay.MarshalCanonicalEnrollmentInput(canonical)
	if err != nil {
		return outcome, err
	}
	if err := writePrivateFile(filepath.Join(options.Output, "canonical-input.json"), append(canonicalDocument, '\n')); err != nil {
		return outcome, err
	}
	const selectedProfile = "minimal-current-sinf"
	if err := ctx.Err(); err != nil {
		return outcome, err
	}
	mappings, stateFiles := canonical.RuntimeFileMappings()
	if stateFiles == 0 {
		return outcome, fmt.Errorf("derive enrollment: %s has no FairPlay state", selectedProfile)
	}
	recovered, err := recovery.Recover(recovery.Options{
		FileMappings: mappings, HardwarePath: canonical.PrivateHardwarePath(), Context: ctx,
		Progress: func(event recovery.Progress) {
			if event.Total == 0 {
				options.report("profile=%s phase=%s", selectedProfile, event.Phase)
				return
			}
			options.report(
				"profile=%s phase=%s progress=%d%% comparisons=%d/%d registries=%d records=%d windows=%d",
				selectedProfile, event.Phase, event.Completed*100/event.Total, event.Completed, event.Total,
				event.RegistryCandidates, event.RecordCandidates, event.WindowCandidates,
			)
		},
	})
	if err != nil {
		return outcome, fmt.Errorf("derive enrollment: %w", err)
	}
	if recovered.Layout.SINFSelector != manifest.App.SelectorID {
		clear(recovered.EnrollmentModel)
		return outcome, fmt.Errorf("recovered SINF selector does not match capture manifest")
	}
	defer clear(recovered.EnrollmentModel)
	candidate := filepath.Join(options.Output, "fairplay-enrollment.candidate.bin")
	if err := writePrivateFile(candidate, recovered.EnrollmentModel); err != nil {
		return outcome, err
	}
	ipa := filepath.Join(options.Capture, filepath.FromSlash(manifest.IPA.Path))
	decrypted := filepath.Join(options.Output, "App.decrypted.ipa")
	decryptionReport := filepath.Join(options.Output, "App.decrypted.json")
	options.report("profile=%s phase=validate-ipa", selectedProfile)
	result, err := fairplay.DecryptIPA(fairplay.DecryptOptions{
		InputPath: ipa, OutputPath: decrypted, ReportPath: decryptionReport, ModelPath: candidate,
	})
	if err != nil {
		return outcome, fmt.Errorf("validate recovered enrollment: %w", err)
	}
	enrollment := filepath.Join(options.Output, "fairplay-enrollment.bin")
	if err := os.Rename(candidate, enrollment); err != nil {
		return outcome, err
	}
	summary := map[string]any{
		"schema": "unfairplay-enrollment-recovery-v1", "success": true,
		"selector":          manifest.App.SelectorID,
		"enrollment_status": manifest.FairPlay.Status, "validation_basis": manifest.FairPlay.ValidationBasis,
		"evaluator_profile":           "typed-current-enrollment",
		"portable_semantic_evaluator": true,
		"canonical_contract":          canonical.Contract, "canonical_input_sha256": canonical.FingerprintSHA256,
		"enrollment_model": enrollment, "decrypted_ipa": decrypted,
		"decrypted_ipa_sha256": result.OutputSHA256, "encrypted_images": result.EncryptedImages,
		"decrypted_pages": result.DecryptedPages, "input_profile": selectedProfile,
		"plaintext_verified":  result.PlaintextVerified,
		"recovery_iterations": recovered.Iterations, "recovery_state_sha256": recovered.StateSHA256,
		"decoded_registry_candidates": recovered.DecodedRegistryCandidates,
		"recovery_layout":             recovered.Layout,
		"validation_source":           validationSource,
		"promotion_gate":              "complete-sinf-and-ipa-validation",
		"reference_code_source":       referenceSource,
	}
	document, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return outcome, err
	}
	report := filepath.Join(options.Output, "recovery-report.json")
	if err := writePrivateFile(report, append(document, '\n')); err != nil {
		return outcome, err
	}
	return Result{Summary: summary, ModelPath: enrollment}, nil
}
