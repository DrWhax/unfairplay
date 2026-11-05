package recovery_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/DrWhax/unfairplay/internal/recovery"
	"github.com/DrWhax/unfairplay/pkg/fairplay"
)

// Private capture inputs are optional and are never stored in the repository.
func TestRecoveryReproducibleLocalCapture(t *testing.T) {
	capture := os.Getenv("UNFAIRPLAY_TEST_CAPTURE")
	if capture == "" {
		t.Skip("local capture not configured")
	}
	manifest, err := fairplay.LoadEnrollmentCapture(capture, true)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := fairplay.NormalizeEnrollmentCapture(capture, manifest)
	if err != nil {
		t.Fatal(err)
	}
	mappings, stateFiles := canonical.RuntimeFileMappings()
	if stateFiles == 0 {
		t.Fatal("capture has no FairPlay state")
	}
	options := recovery.Options{FileMappings: mappings, HardwarePath: canonical.PrivateHardwarePath()}
	first, err := recovery.Recover(options)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(first.EnrollmentModel)
	second, err := recovery.Recover(options)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(second.EnrollmentModel)
	if first.StateSHA256 != second.StateSHA256 || first.Iterations != second.Iterations || !bytes.Equal(first.EnrollmentModel, second.EnrollmentModel) {
		t.Fatal("repeated recovery in one process was not deterministic")
	}
	if manifest.IPA == nil {
		t.Fatal("capture has no validation IPA")
	}
	directory := t.TempDir()
	modelPath := filepath.Join(directory, "model.bin")
	if err := os.WriteFile(modelPath, second.EnrollmentModel, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := fairplay.DecryptIPA(fairplay.DecryptOptions{
		InputPath: filepath.Join(capture, manifest.IPA.Path), ModelPath: modelPath,
		OutputPath: filepath.Join(directory, "out.ipa"), ReportPath: filepath.Join(directory, "out.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.EncryptedImages == 0 || result.DecryptedPages == 0 {
		t.Fatal("no encrypted images were validated")
	}
}
