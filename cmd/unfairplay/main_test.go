package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DrWhax/unfairplay/internal/fairplay"
)

func TestCommandsAreRegistered(t *testing.T) {
	root := newRootCommand()
	for _, name := range []string{"setup", "collect", "recover", "decrypt", "convert-ipa-macos", "verify", "doctor"} {
		command, _, err := root.Find([]string{name})
		if err != nil || command == root || command.Name() != name {
			t.Fatalf("command %s is not registered: %v", name, err)
		}
	}
}

func TestConfiguredVersionOverridesBuildMetadata(t *testing.T) {
	previous := version
	version = "v-test"
	t.Cleanup(func() { version = previous })
	if got := newRootCommand().Version; got != "v-test" {
		t.Fatalf("root version = %q", got)
	}
}

func TestConvertIPAMacOSFlags(t *testing.T) {
	command := newConvertIPAMacOSCommand()
	for _, name := range []string{"input", "output", "model", "credential", "force"} {
		if command.Flags().Lookup(name) == nil {
			t.Fatalf("convert-ipa-macos has no --%s flag", name)
		}
	}
}

func TestSavedModelDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "models")
	t.Setenv(modelDirectoryEnvironment, directory)
	if _, err := selectedModelPath(""); err == nil {
		t.Fatal("missing saved model directory was accepted")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	selected, err := selectedModelPath("")
	if err != nil || selected != directory {
		t.Fatalf("selected model path = %q, %v", selected, err)
	}
	explicit := filepath.Join(t.TempDir(), "explicit.bin")
	selected, err = selectedModelPath(explicit)
	if err != nil || selected != explicit {
		t.Fatalf("explicit model path = %q, %v", selected, err)
	}
}

func TestInstallEnrollmentModel(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private", "models")
	model := []byte("private enrollment model")
	path, digest, reused, err := installEnrollmentModel(directory, "11223344:00000002", model)
	if err != nil || reused || len(digest) != 64 {
		t.Fatalf("install model = %q, %q, %v, %v", path, digest, reused, err)
	}
	for target, mode := range map[string]os.FileMode{directory: 0o700, path: 0o600} {
		info, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("private path %s mode = %v", target, info.Mode().Perm())
		}
	}
	second, secondDigest, reused, err := installEnrollmentModel(directory, "11223344:00000002", model)
	if err != nil || !reused || second != path || secondDigest != digest {
		t.Fatalf("reuse model = %q, %q, %v, %v", second, secondDigest, reused, err)
	}
	if _, _, _, err := installEnrollmentModel(directory, "../unsafe:00000002", model); err == nil {
		t.Fatal("unsafe selector was accepted as a model filename")
	}
}

func TestVerificationOutputSchema(t *testing.T) {
	for _, test := range []struct {
		name, shared, schema string
		hashes               map[string]string
	}{
		{"single", "key-a", "unfairplay-model-verification-v1", map[string]string{"App.sinf": "key-a"}},
		{"shared", "key-a", "unfairplay-model-verification-v1", map[string]string{"App.sinf": "key-a", "Widget.sinf": "key-a"}},
		{"distinct", "", "unfairplay-model-verification-v2", map[string]string{"App.sinf": "key-a", "Widget.sinf": "key-b"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(verificationSummary(fairplay.DecryptResult{
				LogicalKeySHA256: test.shared, LogicalKeySHA256BySINF: test.hashes,
			}))
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]json.RawMessage
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			var schema string
			if err := json.Unmarshal(got["schema"], &schema); err != nil || schema != test.schema {
				t.Fatalf("schema=%q err=%v", schema, err)
			}
			value, hasScalar := got["logical_key_sha256"]
			if test.shared == "" {
				if hasScalar {
					t.Fatal("distinct-key verification emitted legacy scalar")
				}
			} else {
				var hash string
				if !hasScalar || json.Unmarshal(value, &hash) != nil || hash != test.shared {
					t.Fatal("legacy scalar contract changed")
				}
			}
		})
	}
}

func TestCollectExposesArchivedExecutablePath(t *testing.T) {
	root := newRootCommand()
	command, _, err := root.Find([]string{"collect"})
	if err != nil {
		t.Fatal(err)
	}
	if command.Flags().Lookup("installed-executable-path") == nil {
		t.Fatal("collect has no archived executable path override")
	}
	if command.Flags().Lookup("fairplayd") != nil {
		t.Fatal("collect still exposes a fairplayd dependency")
	}
}

func TestRecoverHasNoNativeExecutionFlags(t *testing.T) {
	command := newRecoverCommand()
	for _, name := range []string{"reference-binary", "selection-max-blocks", "trace-stages", "trace-values"} {
		if command.Flags().Lookup(name) != nil {
			t.Fatalf("recover still exposes native execution flag --%s", name)
		}
	}
}

func TestWritePrivateFileFailsIfDestinationExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.bin")
	if err := writePrivateFile(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private file mode = %04o", info.Mode().Perm())
	}
	if err := writePrivateFile(path, []byte("second")); err == nil {
		t.Fatal("private file was overwritten")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first" {
		t.Fatalf("private file changed to %q", data)
	}
}

func TestVerificationSummaryReportsPlaintextCoverage(t *testing.T) {
	for _, verified := range []bool{false, true} {
		got := verificationSummary(fairplay.DecryptResult{PlaintextVerified: verified})
		if got["plaintext_verified"] != verified {
			t.Fatalf("plaintext verification status lost: %v", got)
		}
	}
}

func TestSetupSummaryReportsPlaintextCoverage(t *testing.T) {
	for _, test := range []struct {
		name     string
		verified bool
	}{
		{"available-hashes-verified", true},
		{"missing-plaintext-hashes", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(setupSummary(map[string]any{
				"decrypted_ipa_sha256": "synthetic-ipa-digest",
				"encrypted_images":     2, "decrypted_pages": 3,
				"plaintext_verified": test.verified,
			}))
			if err != nil {
				t.Fatal(err)
			}
			var got struct {
				Schema            string `json:"schema"`
				Success           bool   `json:"success"`
				PlaintextVerified *bool  `json:"plaintext_verified"`
			}
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if got.PlaintextVerified == nil || *got.PlaintextVerified != test.verified {
				t.Fatalf("setup JSON must preserve plaintext_verified=%v: %s", test.verified, data)
			}
			if got.Schema != "unfairplay-setup-v1" || !got.Success {
				t.Fatalf("successful setup contract changed: %s", data)
			}
		})
	}
}
