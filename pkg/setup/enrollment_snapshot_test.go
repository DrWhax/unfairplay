package setup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestInvalidRecoveryNeverPromotesModel(t *testing.T) {
	directory := t.TempDir()
	if _, _, err := validateRecoveredEnrollment(context.Background(), []byte("invalid model"), filepath.Join(directory, "missing.ipa"), directory, "synthetic", nil); err == nil {
		t.Fatal("accepted invalid recovery")
	}
	for _, name := range []string{"fairplay-enrollment.candidate.bin", "fairplay-enrollment.bin", "App.decrypted.ipa"} {
		if _, err := os.Stat(filepath.Join(directory, name)); !os.IsNotExist(err) {
			t.Fatal("failed recovery retained published state", name)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := validateRecoveredEnrollment(ctx, []byte("model"), "unused", directory, "synthetic", nil); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestCopySetupIPAPrivateAndExclusive(t *testing.T) {
	root := t.TempDir()
	src, dst := filepath.Join(root, "input"), filepath.Join(root, "copy")
	if err := os.WriteFile(src, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := copySetupIPA(src, dst); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("changed"), 0644); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dst)
	if err != nil || string(data) != "original" {
		t.Fatal("copy changed", err)
	}
	info, err := os.Stat(dst)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("copy is not private")
	}
	if err := copySetupIPA(src, dst); err == nil {
		t.Fatal("overwrote copy")
	}
	if err := copySetupIPA(root, dst+".directory"); err == nil {
		t.Fatal("accepted nonregular IPA")
	}
}
