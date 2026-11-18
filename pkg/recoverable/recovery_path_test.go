package recoverable

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

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
