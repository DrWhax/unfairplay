package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DrWhax/unfairplay/pkg/fairplay"
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

func TestVerificationSummaryReportsPlaintextCoverage(t *testing.T) {
	for _, verified := range []bool{false, true} {
		got := verificationSummary(fairplay.DecryptResult{PlaintextVerified: verified})
		if got["plaintext_verified"] != verified {
			t.Fatalf("plaintext verification status lost: %v", got)
		}
	}
}
