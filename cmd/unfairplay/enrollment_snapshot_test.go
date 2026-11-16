package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapshotSetupArguments(t *testing.T) {
	for _, args := range [][]string{
		{"--ipa", "missing.ipa"},
		{"--ipa", "missing.ipa", "--app", "App.app", "--enrollment", "snapshot"},
		{"--enrollment", "snapshot"},
		{"--ipa", "missing.ipa", "--enrollment", ""},
		{"--ipa", "missing.ipa", "--enrollment", "snapshot", "--interface", "en0"},
	} {
		cmd := newSetupCommand()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("accepted arguments %v", args)
		}
	}
	cmd := newSetupCommand()
	cmd.SetArgs([]string{"--ipa", "missing.ipa", "--enrollment", "missing.snapshot"})
	if err := cmd.Execute(); err == nil || strings.Contains(err.Error(), "required flag") {
		t.Fatalf("snapshot setup did not reach input loading: %v", err)
	}
}

func TestAppOnlySetupStillReachesCollection(t *testing.T) {
	cmd := newSetupCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--app", filepath.Join(t.TempDir(), "missing.app")})
	if err := cmd.Execute(); err == nil || strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "requires --ipa") {
		t.Fatalf("app-only setup did not reach collection: %v", err)
	}
}

func TestExportEnrollmentRejectsInvalidStateBeforePublication(t *testing.T) {
	root := t.TempDir()
	state, shared := filepath.Join(root, "state"), filepath.Join(root, "shared")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	hardware := filepath.Join(root, "hardware")
	if err := os.WriteFile(hardware, []byte{0, 1, 2, 3, 4, 5}, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "SC Info.sidb"), []byte{0, 7, 0, 11, 1}, 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "snapshot")
	cmd := newExportEnrollmentCommand()
	cmd.SetArgs([]string{"--output", output, "--system-state", state, "--shared-state", shared, "--iomac-file", hardware, "--product-version", "26.0", "--build-version", "synthetic"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("exported unauthenticated state")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("failed export left a snapshot")
	}
	if err := os.WriteFile(output, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatal("did not reject existing output before collection", err)
	}
	data, err := os.ReadFile(output)
	if err != nil || string(data) != "existing" {
		t.Fatal("modified existing snapshot")
	}
}
