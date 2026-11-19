package recoverable

import (
	"archive/zip"
	"encoding/binary"
	"maps"
	"os"
	"path/filepath"
	"testing"

	f "github.com/DrWhax/unfairplay/pkg/fairplay"
	"howett.net/plist"
)

func recoveryPathFixture(t *testing.T, exe string, extra map[string][]byte) *zip.ReadCloser {
	t.Helper()
	p := filepath.Join(t.TempDir(), "input.ipa")
	f, e := os.Create(p)
	if e != nil {
		t.Fatal(e)
	}
	w := zip.NewWriter(f)
	b, e := plist.Marshal(map[string]string{"CFBundleExecutable": exe}, plist.XMLFormat)
	if e != nil {
		t.Fatal(e)
	}
	entries := map[string][]byte{"Payload/Test.app/Info.plist": b}
	for n, b := range extra {
		entries[n] = b
	}
	for n, b := range entries {
		v, e := w.Create(n)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = v.Write(b); e != nil {
			t.Fatal(e)
		}
	}
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	f.Close()
	z, e := zip.OpenReader(p)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { z.Close() })
	return z
}
func TestRecoveryPathFollowsExecutable(t *testing.T) {
	z := recoveryPathFixture(t, "Executable", nil)
	m, e := members(z)
	if e != nil {
		t.Fatal(e)
	}
	p, e := recoveryMemberPath(m)
	if e != nil || p != "Payload/Test.app/SC_Info/Executable.sinf-recovery" {
		t.Fatal("wrong recovery route", e)
	}
}
func TestRecoveryPathRejectsInvalidOrLegacy(t *testing.T) {
	for _, exe := range []string{"", "..", "../Other", "dir/file", "dir\\file"} {
		z := recoveryPathFixture(t, exe, nil)
		m, _ := members(z)
		if _, e := recoveryMemberPath(m); e == nil {
			t.Fatal("unsafe executable accepted")
		}
	}
	for _, n := range []string{"Payload/Test.app/SC_Info/Wrong.sinf-recovery", "Payload/Test.app/SC_Info/AppContentKey.bin", "Payload/Test.app/SC_Info/AppRecovery.json"} {
		z := recoveryPathFixture(t, "Executable", map[string][]byte{n: {1}})
		m, _ := members(z)
		if _, e := recoveryMemberPath(m); e == nil {
			t.Fatal("ambiguous/legacy material accepted")
		}
	}
}

func TestOmitAppleDoubleSidecars(t *testing.T) {
	const app = "Payload/Test.app/"
	const sinf = app + "SC_Info/Test.sinf"
	const sidecar = "__MACOSX/" + app + "SC_Info/._Test.sinf"
	header := make([]byte, 26)
	binary.BigEndian.PutUint32(header[:4], 0x00051607)
	binary.BigEndian.PutUint32(header[4:8], 0x00020000)

	keep := map[string][]byte{
		sinf:                                     {1},
		app + "SC_Info/._Other.sinf":             header,
		"__MACOSX/" + app + "SC_Info/Other.sinf": header,
		"__MACOSX/" + app + "SC_Info/._Invalid.sinf": make([]byte, 26),
		"__MACOSX/" + app + "SC_Info/._Short.sinf":   header[:8],
	}
	entries := maps.Clone(keep)
	entries[sidecar] = header
	entries["__MACOSX/"+app+"SC_Info/._Test.supf"] = header
	z := recoveryPathFixture(t, "Test", entries)
	files, err := members(z)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.OmitAppleDoubleSidecars(files); err != nil {
		t.Fatal(err)
	}
	if len(files) != len(keep)+1 { // Info.plist plus the non-AppleDouble entries.
		t.Fatalf("unexpected member count: %d", len(files))
	}
	for name := range keep {
		if files[name] == nil {
			t.Errorf("removed non-sidecar member %q", name)
		}
	}
	if files[sidecar] != nil || files["__MACOSX/"+app+"SC_Info/._Test.supf"] != nil {
		t.Fatal("retained an AppleDouble sidecar")
	}
}
