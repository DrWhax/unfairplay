package fairplay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReportSeparatesCompletionFromVerification(t *testing.T) {
	dir := t.TempDir()
	destination := testFile(t, dir, "report.json", "previous report")
	const modelBuild = "test-external-model"
	name, err := stagePrivateJSON(destination, decryptionReport{Complete: true, ModelBuild: modelBuild})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(name)
	assertFile(t, destination, "previous report")
	blob, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(blob, &report); err != nil {
		t.Fatal(err)
	}
	if report["complete"] != true || report["plaintext_verified"] != false || report["signature_verified"] != false || report["model_build"] != modelBuild {
		t.Fatalf("ambiguous report: %s", blob)
	}
	if checkPlatform() == nil {
		info, err := os.Stat(name)
		if err != nil || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("report permissions: %v, %v", info, err)
		}
	}
}

func TestReportStagingCleansUpEncodingFailure(t *testing.T) {
	dir := t.TempDir()
	if _, err := stagePrivateJSON(filepath.Join(dir, "report.json"), make(chan int)); err == nil {
		t.Fatal("expected encoding failure")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed report staging left files: %v, %v", entries, err)
	}
}
