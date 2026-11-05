package fairplay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"howett.net/plist"
)

func TestParseIORegistryHardwareMAC(t *testing.T) {
	want := []byte{0xc8, 0x89, 0xf3, 0xdd, 0x0d, 0x56}
	document := map[string]any{
		"IORegistryEntryChildren": []any{
			map[string]any{
				"IOMACAddress": want,
				"IORegistryEntryChildren": []any{
					map[string]any{"BSD Name": "en0", "IOBuiltin": true},
				},
			},
		},
	}
	encoded, err := plist.Marshal(document, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseIORegistryHardwareMAC(encoded, "en0")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("IOMACAddress = %x, want %x", got, want)
	}
	if _, err := parseIORegistryHardwareMAC(encoded, "en9"); err == nil {
		t.Fatal("missing interface was accepted")
	}
}

func TestParseIORegistryHardwareMACSubtrees(t *testing.T) {
	want := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	other := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	controller := func(name string, builtin bool, mac []byte) map[string]any {
		return map[string]any{
			"IOMACAddress": mac,
			"IORegistryEntryChildren": []any{
				map[string]any{"BSD Name": name, "IOBuiltin": builtin},
			},
		}
	}
	for _, test := range []struct {
		name     string
		document any
		wantMAC  bool
	}{
		{"multiple-controllers", []any{controller("en1", true, other), controller("en0", false, other), controller("en0", true, want)}, true},
		{"not-built-in", []any{controller("en0", false, want)}, false},
		{"wrong-interface", []any{controller("en1", true, want)}, false},
		{"short-parent-address", []any{controller("en0", true, want[:5])}, false},
		{"missing-parent-address", []any{map[string]any{
			"IORegistryEntryChildren": []any{map[string]any{"BSD Name": "en0", "IOBuiltin": true, "IOMACAddress": want}},
		}}, false},
		{"empty", []any{}, false},
		{"invalid-root", "not a registry", false},
		{"invalid-subtree", []any{"not a registry"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := plist.Marshal(test.document, plist.XMLFormat)
			if err != nil {
				t.Fatal(err)
			}
			got, err := parseIORegistryHardwareMAC(encoded, "en0")
			if test.wantMAC {
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("IOMACAddress = %x, err = %v; want %x", got, err, want)
				}
			} else if err == nil {
				t.Fatal("invalid hardware identity was accepted")
			}
		})
	}
}

func TestParseIORegistryHardwareMACRejectsInvalidXML(t *testing.T) {
	for _, document := range []string{
		`<plist><array><dict><key>unrelated</key><string>` + "\x01" + `</string></dict></array></plist>`,
		`<plist><array><dict>`,
	} {
		if _, err := parseIORegistryHardwareMAC([]byte(document), "en0"); err == nil {
			t.Fatal("invalid XML was accepted")
		}
	}
}

func TestExternalIORegistryHardwareMAC(t *testing.T) {
	macPath := os.Getenv("UNFAIRPLAY_IOMAC_FILE")
	if runtime.GOOS != "darwin" || macPath == "" {
		t.Skip("private macOS hardware identity control is not configured")
	}
	want, err := os.ReadFile(macPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(want)
	if len(want) != 6 {
		t.Fatal("private hardware identity control must contain six bytes")
	}
	got, err := ioregHardwareMAC("en0")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	if !bytes.Equal(got, want) {
		t.Fatal("hardware identity does not match the private control")
	}
}

func currentLayoutSINF(selector SINFSelector) []byte {
	user := make([]byte, 4)
	key := make([]byte, 4)
	user[0], user[1], user[2], user[3] = byte(selector.User>>24), byte(selector.User>>16), byte(selector.User>>8), byte(selector.User)
	key[0], key[1], key[2], key[3] = byte(selector.Key>>24), byte(selector.Key>>16), byte(selector.Key>>8), byte(selector.Key)
	fields := append(testAtom("user", user), testAtom("key ", key)...)
	rights := make([]byte, 88)
	for index, name := range append(currentSINFRequiredRights[:], "hi32") {
		copy(rights[index*8:index*8+4], name)
	}
	fields = append(fields, testAtom("righ", rights)...)
	fields = append(fields, testAtom("priv", make([]byte, 448))...)
	return testAtom("sinf", testAtom("schi", fields))
}

func TestInspectSINFAndModel(t *testing.T) {
	selector := SINFSelector{User: 0x12345678, Key: 2}
	diagnostic, err := InspectSINF(currentLayoutSINF(selector))
	if err != nil {
		t.Fatal(err)
	}
	if diagnostic.Selector != selector || !diagnostic.CurrentLayout || diagnostic.LegacyMarkers || diagnostic.PrivateBytes != 448 || diagnostic.RightsBytes != 88 {
		t.Fatalf("unexpected SINF diagnostic: %#v", diagnostic)
	}
	modelPath := filepath.Join(t.TempDir(), "model.bin")
	if err := os.WriteFile(modelPath, selectorBoundModelPack(t, selector), 0o600); err != nil {
		t.Fatal(err)
	}
	model, err := InspectEnrollmentModel(modelPath)
	if err != nil {
		t.Fatal(err)
	}
	if model.Version != 2 || model.Selector == nil || *model.Selector != selector {
		t.Fatalf("unexpected model diagnostic: %#v", model)
	}
}

func TestInspectSINFStructuralCurrentLayouts(t *testing.T) {
	credential := macOSTestCredential()
	for _, test := range []struct {
		name                      string
		sinf                      []byte
		privateBytes, rightsBytes int
	}{
		{"short", macOSTestCurrentSINFLayout(t, credential, 1, true), 440, 80},
		{"standard", macOSTestCurrentSINF(t, credential, 1), 448, 88},
		{"extended", macOSTestCurrentSINFWithRights(t, credential, 1, []string{
			"veID", "plat", "aver", "tran", "sing", "song", "tool", "medi", "mode", "hi32", "xtra",
		}), 456, 96},
	} {
		t.Run(test.name, func(t *testing.T) {
			diagnostic, err := InspectSINF(test.sinf)
			if err != nil {
				t.Fatal(err)
			}
			if !diagnostic.CurrentLayout || diagnostic.PrivateBytes != test.privateBytes || diagnostic.RightsBytes != test.rightsBytes {
				t.Fatalf("diagnostic = %#v", diagnostic)
			}
		})
	}
}

func TestFairPlayBuildIdentityDoesNotSelectAlgorithm(t *testing.T) {
	typed, known := ResolveFairPlayBuildSupport("", "future-build")
	if known || !typed.Recovery || typed.Decrypt || typed.Status != "portable-validation-required" || typed.Profile != "typed-current-enrollment" {
		t.Fatalf("binary-independent support = %#v, known=%v", typed, known)
	}
	const unknownHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	support, known := ResolveFairPlayBuildSupport(unknownHash, "future-build")
	if known || !support.Recovery || support.Decrypt || support.Status != "portable-validation-required" ||
		support.Profile != "typed-current-enrollment" {
		t.Fatalf("unknown build support = %#v, known=%v", support, known)
	}
	invalid, known := ResolveFairPlayBuildSupport("not-a-sha256", "future-build")
	if known || invalid.Recovery || invalid.Status != "invalid-fairplayd-identity" {
		t.Fatalf("invalid build support = %#v, known=%v", invalid, known)
	}
}

func TestBinaryIndependentManifestOmitsFairPlayd(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "capture")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	private := []byte("private fixture")
	if err := os.WriteFile(filepath.Join(directory, "private.bin"), private, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(private)
	manifest := EnrollmentCaptureManifest{
		Schema: EnrollmentCaptureSchema,
		Files: []EnrollmentCaptureFile{{
			Path: "private.bin", Bytes: int64(len(private)), SHA256: hex.EncodeToString(digest[:]), Mode: "0600",
		}},
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "fairplayd") {
		t.Fatalf("binary-independent manifest retained fairplayd: %s", encoded)
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadEnrollmentCapture(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.FairPlay.Status != "portable-validation-required" || !loaded.FairPlay.Recovery || loaded.FairPlay.Decrypt {
		t.Fatalf("binary-independent capture support = %#v", loaded.FairPlay)
	}
}

func TestLoadEnrollmentCaptureIntegrity(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "capture")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(directory, "private.bin")
	private := []byte("private fixture")
	if err := os.WriteFile(privatePath, private, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(private)
	manifest := EnrollmentCaptureManifest{
		Schema:    EnrollmentCaptureSchema,
		FairPlayd: EnrollmentCaptureFile{SHA256: strings.Repeat("ab", sha256.Size)},
		FairPlay:  FairPlayBuildSupport{Status: "stale-research-only"},
		Files: []EnrollmentCaptureFile{{
			Path: "private.bin", Bytes: int64(len(private)), SHA256: hex.EncodeToString(digest[:]), Mode: "0600",
		}},
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadEnrollmentCapture(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.FairPlay.Status != "portable-validation-required" || loaded.FairPlay.Profile != "typed-current-enrollment" || loaded.FairPlay.Decrypt {
		t.Fatalf("capture support metadata was not refreshed: %#v", loaded.FairPlay)
	}
	if err := os.WriteFile(privatePath, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnrollmentCapture(directory, true); err == nil {
		t.Fatal("modified capture was accepted")
	}
	manifest.Files[0].Path = "../outside.bin"
	encoded, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnrollmentCapture(directory, true); err == nil {
		t.Fatal("capture path traversal was accepted")
	}
}

func TestLoadLegacyCaptureSchemas(t *testing.T) {
	for _, schema := range []string{legacyUnfairPlayEnrollmentCaptureSchema, legacyEnrollmentCaptureSchema} {
		t.Run(schema, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "capture")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			manifest := EnrollmentCaptureManifest{
				Schema: schema,
				FairPlayd: EnrollmentCaptureFile{
					SHA256: strings.Repeat("cd", sha256.Size),
				},
			}
			encoded, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "manifest.json"), encoded, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadEnrollmentCapture(directory, false); err != nil {
				t.Fatalf("legacy capture schema was rejected: %v", err)
			}
		})
	}
}
