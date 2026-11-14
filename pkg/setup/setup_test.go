package setup

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRequiresModelDirectory(t *testing.T) {
	_, err := Run(context.Background(), Options{})
	if err == nil || !strings.Contains(err.Error(), "ModelDirectory") {
		t.Fatalf("Run without a model directory = %v", err)
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

func TestSetupSummaryPreservesValidationSource(t *testing.T) {
	for _, source := range []string{"installed-app", "provided"} {
		summary := setupSummary(map[string]any{"validation_source": source})
		if summary["validation_source"] != source {
			t.Fatal("setup summary lost validation provenance")
		}
	}
}
