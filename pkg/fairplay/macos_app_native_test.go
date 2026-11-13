package fairplay

import (
	"archive/zip"
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"howett.net/plist"
)

// This opt-in control uses only a locally compiled synthetic program. It tests
// native signing and execution, not UIKit or private application compatibility.
func TestNativeMacOSAppConversion(t *testing.T) {
	if os.Getenv("UNFAIRPLAY_TEST_MACOS_CONVERSION") != "1" || runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("opt-in Apple silicon native conversion control")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "main.c")
	binaryPath := filepath.Join(dir, "Synthetic")
	if err := os.WriteFile(source, []byte("int main(void) { return 0; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/bin/xcrun", "clang", "-target", "arm64-apple-ios14.0-macabi", source, "-o", binaryPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile synthetic Catalyst control: %v: %s", err, output)
	}
	blob, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	// Make a synthetic iOS input to exercise actual platform retargeting.
	end := 32 + int(binary.LittleEndian.Uint32(blob[20:24]))
	found := false
	for cursor := 32; cursor < end; {
		size := int(binary.LittleEndian.Uint32(blob[cursor+4 : cursor+8]))
		if binary.LittleEndian.Uint32(blob[cursor:cursor+4]) == lcBuildVersion {
			binary.LittleEndian.PutUint32(blob[cursor+8:cursor+12], 2)
			found = true
		}
		cursor += size
	}
	if !found {
		t.Fatal("compiler emitted no build version")
	}
	info, _ := plist.Marshal(map[string]any{"CFBundleExecutable": "Synthetic", "CFBundleIdentifier": "org.example.unfairplay.synthetic", "CFBundlePackageType": "APPL", "CFBundleVersion": "1"}, plist.XMLFormat)
	libraryPath := filepath.Join(dir, "Library")
	command = exec.Command("/usr/bin/xcrun", "clang", "-target", "arm64-apple-ios14.0-macabi", "-dynamiclib", source, "-o", libraryPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile synthetic framework: %v: %s", err, output)
	}
	library, err := os.ReadFile(libraryPath)
	if err != nil {
		t.Fatal(err)
	}
	frameworkInfo, err := plist.Marshal(map[string]any{"CFBundleExecutable": "Library", "CFBundleIdentifier": "org.example.unfairplay.synthetic.library", "CFBundlePackageType": "FMWK", "CFBundleVersion": "1"}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "synthetic.ipa")
	file, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for name, data := range map[string][]byte{"Payload/Synthetic.app/Info.plist": info, "Payload/Synthetic.app/Synthetic": blob, "Payload/Synthetic.app/Frameworks/Library.framework/Library": library, "Payload/Synthetic.app/Frameworks/Library.framework/Info.plist": frameworkInfo} {
		w, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "Synthetic.app")
	if _, err := ConvertDecryptedIPAToMacOS(context.Background(), MacOSAppOptions{input, output}); err != nil {
		t.Fatal(err)
	}
	if data, err := exec.Command(filepath.Join(output, "Synthetic")).CombinedOutput(); err != nil {
		t.Fatalf("execute synthetic converted binary: %v: %s", err, data)
	}
}
