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

	// The same private control must also recover using only SIDB/hardware and
	// licenses from the IPA, without the installed executable or installed SINF.
	var snapshot fairplay.EnrollmentSnapshot
	snapshot.ProductVersion, snapshot.BuildVersion = manifest.ProductVersion, manifest.BuildVersion
	hardware, err := os.ReadFile(canonical.PrivateHardwarePath())
	if err != nil {
		t.Fatal(err)
	}
	copy(snapshot.Hardware[:], hardware)
	clear(hardware)
	defer snapshot.Clear()
	for _, sidb := range canonical.SIDBs {
		data, readErr := os.ReadFile(filepath.Join(capture, filepath.FromSlash(sidb.File.CapturePath)))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if snapshot.SIDB != nil {
			equal := bytes.Equal(snapshot.SIDB, data)
			clear(data)
			if !equal {
				t.Fatal("private control has distinct SIDB containers")
			}
		} else {
			snapshot.SIDB = data
		}
	}
	encoded, err := snapshot.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := fairplay.ParseEnrollmentSnapshot(encoded)
	clear(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Clear()
	ipa := filepath.Join(capture, manifest.IPA.Path)
	licenses, err := fairplay.ReadIPAEnrollmentInputs(ipa)
	if err != nil {
		t.Fatal(err)
	}
	defer licenses.Clear()
	fromSnapshot, err := recovery.RecoverEnrollmentSnapshot(t.Context(), parsed, licenses, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(fromSnapshot.EnrollmentModel)
	if !bytes.Equal(first.EnrollmentModel, fromSnapshot.EnrollmentModel) || first.Layout != fromSnapshot.Layout || first.StateSHA256 != fromSnapshot.StateSHA256 {
		t.Fatal("snapshot/IPA recovery differs from installed-app recovery")
	}
	if err := os.WriteFile(modelPath, fromSnapshot.EnrollmentModel, 0600); err != nil {
		t.Fatal(err)
	}
	snapshotResult, err := fairplay.DecryptIPA(fairplay.DecryptOptions{InputPath: ipa, ModelPath: modelPath, OutputPath: filepath.Join(directory, "snapshot.ipa"), ReportPath: filepath.Join(directory, "snapshot.json")})
	if err != nil {
		t.Fatal(err)
	}
	if snapshotResult.OutputSHA256 != result.OutputSHA256 || snapshotResult.PlaintextVerified != result.PlaintextVerified || snapshotResult.EncryptedImages != result.EncryptedImages || snapshotResult.DecryptedPages != result.DecryptedPages {
		t.Fatal("snapshot end-to-end validation differs")
	}
}
