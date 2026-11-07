package fairplay

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadEnrollmentModelRegistry(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	first := selectorBoundModelPack(t, SINFSelector{User: 1, Key: 2})
	second := selectorBoundModelPack(t, SINFSelector{User: 3, Key: 4})
	for name, pack := range map[string][]byte{"first.bin": first, "second.bin": second} {
		if err := os.WriteFile(filepath.Join(directory, name), pack, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(directory, "README.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	packs, err := readEnrollmentModelRegistry(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer clearModelPacks(packs)
	if len(packs) != 2 {
		t.Fatalf("read %d models, want 2", len(packs))
	}
}

func TestReadEnrollmentModelRegistryRejectsUnsafeFiles(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	model := filepath.Join(directory, "unsafe.bin")
	if err := os.WriteFile(model, selectorBoundModelPack(t, SINFSelector{User: 1, Key: 2}), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readEnrollmentModelRegistry(directory); err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("unsafe permissions were accepted: %v", err)
	}
}

func TestValidatePathsAcceptsEnrollmentModelRegistry(t *testing.T) {
	options := testOptions(t)
	options.ModelPath = t.TempDir()
	validated, err := validatePaths(options)
	if err != nil {
		t.Fatal(err)
	}
	if validated.ModelPath == "" {
		t.Fatal("model registry path was lost")
	}
}
