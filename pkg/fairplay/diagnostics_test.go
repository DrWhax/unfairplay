package fairplay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestDoctorFairPlayNextActions(t *testing.T) {
	t.Run("missing capture", func(t *testing.T) {
		report := DoctorFairPlay(filepath.Join(t.TempDir(), "missing"), "", "")
		if report.CaptureVerified {
			t.Fatal("missing capture was verified")
		}
		want := []string{"collect native enrollment with unfairplay collect"}
		if !slices.Equal(report.NextActions, want) {
			t.Fatalf("next actions = %q, want %q", report.NextActions, want)
		}
	})

	t.Run("capture without model", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "capture")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		manifest := EnrollmentCaptureManifest{Schema: EnrollmentCaptureSchema}
		encoded, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "manifest.json"), encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		report := DoctorFairPlay(directory, "", "")
		if !report.CaptureVerified {
			t.Fatalf("capture was not loaded: %v", report.Errors)
		}
		want := []string{"recover fairplay-enrollment.bin with unfairplay recover"}
		if !slices.Equal(report.NextActions, want) {
			t.Fatalf("next actions = %q, want %q", report.NextActions, want)
		}
	})
}
