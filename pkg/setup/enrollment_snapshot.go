package setup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/DrWhax/unfairplay/internal/recovery"
	"github.com/DrWhax/unfairplay/pkg/fairplay"
)

// ExportEnrollment writes one authenticated private enrollment snapshot without
// selecting an app. The output parent must exist; existing files are preserved.
func ExportEnrollment(ctx context.Context, options fairplay.EnrollmentExportOptions, output string) (map[string]any, error) {
	if output == "" {
		return nil, fmt.Errorf("--output must be nonempty")
	}
	parent, err := os.Stat(filepath.Dir(output))
	if err != nil {
		return nil, err
	}
	if !parent.IsDir() {
		return nil, fmt.Errorf("snapshot output parent must be an existing directory")
	}
	if _, err := os.Lstat(output); err == nil {
		return nil, fmt.Errorf("snapshot output already exists")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snapshot, err := fairplay.CollectEnrollmentSnapshot(options)
	if err != nil {
		return nil, err
	}
	defer snapshot.Clear()
	if err := recovery.ValidateEnrollmentSnapshot(ctx, snapshot); err != nil {
		return nil, fmt.Errorf("validate enrollment state: %w", err)
	}
	data, err := snapshot.MarshalBinary()
	if err != nil {
		return nil, err
	}
	defer clear(data)
	if err := writePrivateFile(output, data); err != nil {
		return nil, err
	}
	if err := restoreInvokingUserOwnership(output); err != nil {
		return nil, err
	}
	return map[string]any{"schema": "unfairplay-enrollment-export-v1", "success": true, "snapshot": output,
		"build": snapshot.BuildVersion, "container_authenticated": true, "model_validated": false,
		"warning": "This private snapshot contains enrollment state. Keep it secret; setup still requires a matching personalized IPA."}, nil
}

// Both setup paths share the same model promotion gate. Failed candidates are
// removed even when diagnostic work is retained.
func validateRecoveredEnrollment(ctx context.Context, model []byte, ipa, output, profile string, progress func(string)) (string, fairplay.DecryptResult, error) {
	var result fairplay.DecryptResult
	if err := ctx.Err(); err != nil {
		return "", result, err
	}
	candidate := filepath.Join(output, "fairplay-enrollment.candidate.bin")
	if err := writePrivateFile(candidate, model); err != nil {
		return "", result, err
	}
	defer os.Remove(candidate)
	RecoverOptions{Progress: progress}.report("profile=%s phase=validate-ipa", profile)
	result, err := fairplay.DecryptIPA(fairplay.DecryptOptions{
		InputPath: ipa, OutputPath: filepath.Join(output, "App.decrypted.ipa"),
		ReportPath: filepath.Join(output, "App.decrypted.json"), ModelPath: candidate,
	})
	if err != nil {
		return "", result, fmt.Errorf("validate recovered enrollment: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return "", result, err
	}
	enrollment := filepath.Join(output, "fairplay-enrollment.bin")
	if err := os.Link(candidate, enrollment); err != nil {
		return "", result, err
	}
	return enrollment, result, nil
}

func recoverSnapshotEnrollment(ctx context.Context, snapshotPath, ipaPath, work string, progress func(string)) (Result, string, error) {
	var outcome Result
	snapshot, err := fairplay.ReadEnrollmentSnapshot(snapshotPath)
	if err != nil {
		return outcome, "", err
	}
	defer snapshot.Clear()
	// Freeze the IPA so license selection and final validation use the same
	// bytes, even if the caller replaces the original file during recovery.
	ipa := filepath.Join(work, "input.ipa")
	if err := copySetupIPA(ipaPath, ipa); err != nil {
		return outcome, "", err
	}
	licenses, err := fairplay.ReadIPAEnrollmentInputs(ipa)
	if err != nil {
		return outcome, "", err
	}
	defer licenses.Clear()
	const profile = "snapshot-ipa-sinf"
	recovered, err := recovery.RecoverEnrollmentSnapshot(ctx, snapshot, licenses, func(event recovery.Progress) {
		RecoverOptions{Progress: progress}.report("profile=%s phase=%s completed=%d total=%d", profile, event.Phase, event.Completed, event.Total)
	})
	if err != nil {
		return outcome, "", fmt.Errorf("derive enrollment from snapshot: %w", err)
	}
	defer clear(recovered.EnrollmentModel)
	selector := licenses.Selector.Identifier()
	if recovered.Layout.SINFSelector != selector {
		return outcome, "", fmt.Errorf("recovered selector differs from IPA")
	}
	directory := filepath.Join(work, "recovery")
	if err := os.Mkdir(directory, 0700); err != nil {
		return outcome, "", err
	}
	model, result, err := validateRecoveredEnrollment(ctx, recovered.EnrollmentModel, ipa, directory, profile, progress)
	if err != nil {
		return outcome, "", err
	}
	summary := map[string]any{
		"schema": "unfairplay-snapshot-recovery-v1", "success": true, "selector": selector,
		"enrollment_model": model, "decrypted_ipa": result.OutputPath, "decrypted_ipa_sha256": result.OutputSHA256,
		"encrypted_images": result.EncryptedImages, "decrypted_pages": result.DecryptedPages, "plaintext_verified": result.PlaintextVerified,
		"recovery_layout": recovered.Layout, "recovery_iterations": recovered.Iterations, "recovery_state_sha256": recovered.StateSHA256,
		"validation_source": "provided", "reference_code_source": "typed-go", "promotion_gate": "complete-sinf-and-ipa-validation",
	}
	document, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return outcome, "", err
	}
	if err := writePrivateFile(filepath.Join(directory, "recovery-report.json"), append(document, '\n')); err != nil {
		return outcome, "", err
	}
	return Result{ModelPath: model, Summary: summary}, selector, nil
}

func copySetupIPA(source, destination string) error {
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("setup IPA must be a regular file")
	}
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, f)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
