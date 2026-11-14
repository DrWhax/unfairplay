package fairplay

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"howett.net/plist"
)

func installedAppFixture(t *testing.T) string {
	t.Helper()
	app := filepath.Join(t.TempDir(), "Synthetic.app")
	fixture := syntheticCurrentSINFFixture(t, 42, 7, 88, [16]byte{1, 2, 3})
	image, supf, _ := multiSINFImage(t, fixture.logical, 0xd503201f)
	info, err := plist.Marshal(appInfo{BundleIdentifier: "org.example.synthetic", Executable: "Synthetic"}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	for relative, data := range map[string][]byte{
		"Info.plist": info, "Synthetic": image, "SC_Info/Synthetic.sinf": fixture.sinf, "SC_Info/Synthetic.v5.supf": supf,
		"Frameworks/Helper.framework/Helper": image, "Frameworks/Helper.framework/SC_Info/Helper.sinf": fixture.sinf, "Frameworks/Helper.framework/SC_Info/Helper.v5.supf": supf,
		"PlugIns/Widget.appex/Widget": image, "PlugIns/Widget.appex/SC_Info/Widget.sinf": fixture.sinf, "PlugIns/Widget.appex/SC_Info/Widget.v5.supf": supf, "resource.txt": []byte("synthetic resource"),
	} {
		path := filepath.Join(app, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return app
}

func TestInstalledValidationIPAPreservesCompleteBundle(t *testing.T) {
	app := installedAppFixture(t)
	destination := filepath.Join(t.TempDir(), "validation.ipa")
	descriptor, err := installedValidationIPA(app, destination)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || descriptor.Mode != "0600" {
		t.Fatal("validation archive is not private")
	}
	digest, size, err := digestFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if digest != descriptor.SHA256 || size != descriptor.Bytes {
		t.Fatal("descriptor does not bind archive")
	}
	archive, err := zip.OpenReader(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	files := 0
	for _, entry := range archive.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		relative := strings.TrimPrefix(entry.Name, "Payload/App.app/")
		if relative == entry.Name {
			t.Fatal("member escapes app root")
		}
		original, err := os.ReadFile(filepath.Join(app, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		packed, err := zipBytes(entry)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(original, packed) {
			t.Fatalf("archive changed %s", relative)
		}
		files++
	}
	if files != 11 {
		t.Fatalf("preserved %d files", files)
	}
	inventory, reader, err := openIPAInventory(destination)
	if err != nil {
		t.Fatal(err)
	}
	reader.Close()
	if len(inventory.images) != 3 {
		t.Fatalf("nested encrypted images = %d", len(inventory.images))
	}
}

func TestInstalledValidationIPARejectsIncompleteOrUnencryptedInput(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"missing licenses", func(t *testing.T, app string) {
			if err := os.RemoveAll(filepath.Join(app, "SC_Info")); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing supf", func(t *testing.T, app string) {
			if err := os.Remove(filepath.Join(app, "SC_Info/Synthetic.v5.supf")); err != nil {
				t.Fatal(err)
			}
		}},
		{"malformed macho", func(t *testing.T, app string) {
			if err := os.WriteFile(filepath.Join(app, "Synthetic"), []byte{0xcf, 0xfa, 0xed, 0xfe}, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"all decrypted", func(t *testing.T, app string) {
			for _, relative := range []string{"Synthetic", "Frameworks/Helper.framework/Helper", "PlugIns/Widget.appex/Widget"} {
				p := filepath.Join(app, filepath.FromSlash(relative))
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				binary.LittleEndian.PutUint32(data[48:52], 0)
				if err := os.WriteFile(p, data, 0o700); err != nil {
					t.Fatal(err)
				}
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := installedAppFixture(t)
			test.mutate(t, app)
			destination := filepath.Join(t.TempDir(), "validation.ipa")
			if _, err := installedValidationIPA(app, destination); err == nil {
				t.Fatal("accepted unusable installed bundle")
			}
			if _, err := os.Stat(destination); !os.IsNotExist(err) {
				t.Fatal("left invalid validation archive")
			}
		})
	}
}

func TestInstalledArchiveRejectsSymlinksAndUnsafeNames(t *testing.T) {
	for _, test := range []string{"symlink", "unsafe-name"} {
		t.Run(test, func(t *testing.T) {
			app := installedAppFixture(t)
			if test == "symlink" {
				if err := os.Symlink("resource.txt", filepath.Join(app, "link")); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(filepath.Join(app, "bad\\name"), []byte("synthetic"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			destination := filepath.Join(t.TempDir(), "validation.ipa")
			if _, err := archiveInstalledApp(app, destination); err == nil {
				t.Fatal("accepted unsupported member")
			}
			if _, err := os.Stat(destination); !os.IsNotExist(err) {
				t.Fatal("left partial archive")
			}
		})
	}
}

func TestInstalledArchiveDoesNotReplaceExistingFile(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "existing.ipa")
	if err := os.WriteFile(destination, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := archiveInstalledApp(installedAppFixture(t), destination); err == nil {
		t.Fatal("replaced existing archive")
	}
	data, err := os.ReadFile(destination)
	if err != nil || string(data) != "keep" {
		t.Fatal("changed preexisting destination")
	}
}

func TestCaptureIPASourceMetadata(t *testing.T) {
	for _, test := range []struct {
		source           string
		hasIPA, accepted bool
	}{
		{"", false, true}, {"provided", true, true}, {"installed-app", true, true}, {"unknown", true, false}, {"installed-app", false, false},
	} {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		manifest := EnrollmentCaptureManifest{Schema: EnrollmentCaptureSchema, IPASource: test.source}
		if test.hasIPA {
			manifest.IPA = &EnrollmentCaptureFile{Path: "ipa/App.ipa"}
		}
		data, _ := json.Marshal(manifest)
		if err := os.WriteFile(filepath.Join(directory, "manifest.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadEnrollmentCapture(directory, false)
		if (err == nil) != test.accepted {
			t.Fatalf("source %q hasIPA=%v err=%v", test.source, test.hasIPA, err)
		}
	}
}

func TestInstalledWrapperNormalization(t *testing.T) {
	outer := filepath.Join(t.TempDir(), "Outer.app")
	inner := filepath.Join(outer, "Wrapper", "Inner.app")
	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("Wrapper/Inner.app", filepath.Join(outer, "WrappedBundle")); err != nil {
		t.Fatal(err)
	}
	resolved, err := normalizeInstalledApp(outer)
	if err != nil || resolved != inner {
		t.Fatalf("normalize wrapper = %q %v", resolved, err)
	}
}

func TestExternalInstalledValidationIPA(t *testing.T) {
	app := os.Getenv("UNFAIRPLAY_INSTALLED_APP")
	if runtime.GOOS != "darwin" || app == "" {
		t.Skip("opt-in installed iOS app control")
	}
	normalized, err := normalizeInstalledApp(app)
	if err != nil {
		t.Fatal("normalize installed app:", err)
	}
	path := filepath.Join(t.TempDir(), "validation.ipa")
	if _, err := installedValidationIPA(normalized, path); err != nil {
		t.Fatal("installed validation archive:", err)
	}
	t.Log("private installed-app control: complete archive inventory accepted")
	if model := os.Getenv("UNFAIRPLAY_INSTALLED_MODEL"); model != "" {
		result, err := DecryptIPA(DecryptOptions{
			InputPath: path, ModelPath: model,
			OutputPath: filepath.Join(t.TempDir(), "decrypted.ipa"),
			ReportPath: filepath.Join(t.TempDir(), "report.json"),
		})
		if err != nil {
			t.Fatal("private installed-app decryption control:", err)
		}
		t.Logf("private installed-app control: decryption complete; plaintext_verified=%v", result.PlaintextVerified)
	}
}

func TestInstalledArchiveDecryptsWithExistingPipeline(t *testing.T) {
	app := installedAppFixture(t)
	work := t.TempDir()
	input := filepath.Join(work, "input.ipa")
	if _, err := installedValidationIPA(app, input); err != nil {
		t.Fatal(err)
	}
	model := filepath.Join(work, "model.bin")
	if err := os.WriteFile(model, selectorBoundModelPack(t, SINFSelector{User: 42, Key: 7}), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := DecryptIPA(DecryptOptions{InputPath: input, OutputPath: filepath.Join(work, "output.ipa"), ReportPath: filepath.Join(work, "output.json"), ModelPath: model})
	if err != nil {
		t.Fatal(err)
	}
	if result.EncryptedImages != 3 || !result.PlaintextVerified {
		t.Fatal("installed validation archive did not pass complete plaintext verification")
	}
}

func TestCollectEnrollmentBuildsInstalledArchiveAndHonorsOverride(t *testing.T) {
	for _, provided := range []bool{false, true} {
		t.Run(map[bool]string{false: "installed-app", true: "provided"}[provided], func(t *testing.T) {
			app := installedAppFixture(t)
			work := t.TempDir()
			mac := filepath.Join(work, "mac.bin")
			if err := os.WriteFile(mac, []byte{2, 0, 0, 0, 0, 1}, 0o600); err != nil {
				t.Fatal(err)
			}
			state := filepath.Join(work, "state")
			if err := os.Mkdir(state, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(state, "SC Info.sidb"), []byte("synthetic state; not used for recovery"), 0o600); err != nil {
				t.Fatal(err)
			}
			options := EnrollmentCollectOptions{AppPath: app, OutputPath: filepath.Join(work, "capture"), MACAddressPath: mac, ProductVersion: "synthetic", BuildVersion: "synthetic", SystemStatePath: state, SharedStatePath: filepath.Join(work, "absent-shared"), ADIPath: filepath.Join(work, "absent-adi")}
			if provided {
				options.IPAPath = filepath.Join(work, "provided.ipa")
				if _, err := installedValidationIPA(app, options.IPAPath); err != nil {
					t.Fatal(err)
				}
				// An explicit input must not silently attempt to archive the installed
				// resources instead, even when that route would fail.
				if err := os.Symlink("resource.txt", filepath.Join(app, "unsupported-link")); err != nil {
					t.Fatal(err)
				}
			}
			manifest, err := CollectEnrollment(options)
			if err != nil {
				t.Fatal(err)
			}
			expected := "installed-app"
			if provided {
				expected = "provided"
			}
			if manifest.IPA == nil || manifest.IPASource != expected || manifest.App.TargetSINFPath == "" {
				t.Fatal("missing validation archive provenance")
			}
			if _, err := LoadEnrollmentCapture(options.OutputPath, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInstalledArchiveRejectsCaseCollisions(t *testing.T) {
	app := installedAppFixture(t)
	file, err := os.OpenFile(filepath.Join(app, "RESOURCE.txt"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if os.IsExist(err) {
		t.Skip("case-insensitive filesystem cannot represent this fixture")
	}
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	destination := filepath.Join(t.TempDir(), "validation.ipa")
	if _, err := archiveInstalledApp(app, destination); err == nil {
		t.Fatal("case-colliding paths accepted")
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatal("partial archive retained")
	}
}

func TestInstalledArchiveRejectsOutputInsideSource(t *testing.T) {
	app := installedAppFixture(t)
	destination := filepath.Join(app, "capture", "self.ipa")
	if _, err := archiveInstalledApp(app, destination); err == nil {
		t.Fatal("allowed archive to include itself")
	}
	if _, err := os.Stat(filepath.Dir(destination)); !os.IsNotExist(err) {
		t.Fatal("created output inside source app")
	}
	outside := filepath.Join(t.TempDir(), "source-link")
	if err := os.Symlink(app, outside); err != nil {
		t.Fatal(err)
	}
	if _, err := archiveInstalledApp(app, filepath.Join(outside, "capture", "self.ipa")); err == nil {
		t.Fatal("allowed symlinked output inside source app")
	}
}
