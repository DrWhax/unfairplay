package fairplay

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func researchFixture(t *testing.T, b []byte) map[string]*zip.File {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, e := w.Create("Payload/App.app/Frameworks/F.framework/F")
	if e != nil {
		t.Fatal(e)
	}
	f.Write(b)
	w.Close()
	z, e := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if e != nil {
		t.Fatal(e)
	}
	return map[string]*zip.File{z.File[0].Name: z.File[0]}
}
func researchThin(size uint32) []byte {
	b := make([]byte, 8192)
	put := func(o int, v uint32) { binary.LittleEndian.PutUint32(b[o:], v) }
	put(0, mhMagic64)
	put(4, cpuTypeARM64)
	put(16, 1)
	put(20, 24)
	put(32, lcEncryptionInfo64)
	put(36, 24)
	put(40, 4096)
	put(44, size)
	return b
}
func TestResearchInertClassification(t *testing.T) {
	for _, size := range []uint32{0, 4096} {
		routes, e := unencryptedLicenseRoutes(researchFixture(t, researchThin(size)))
		if e != nil {
			t.Fatal(e)
		}
		p := "Payload/App.app/Frameworks/F.framework/SC_Info/F.sinf"
		if routes[p] != (size == 0) {
			t.Fatal("wrong inert classification")
		}
		for _, suffix := range []string{".supf", ".v5.supf", ".supp", ".v4.supp"} {
			if unusedComponentEnvelope("Payload/App.app/Frameworks/F.framework/SC_Info/F"+suffix, routes) != (size == 0) {
				t.Fatal("wrong envelope ownership")
			}
		}
		if unusedComponentEnvelope("Payload/App.app/Frameworks/F.framework/SC_Info/Other.supf", routes) {
			t.Fatal("accepted unrelated envelope")
		}
	}
}
func TestResearchMalformedMachORejected(t *testing.T) {
	b := researchThin(0)
	binary.LittleEndian.PutUint32(b[36:], 7)
	if _, e := unencryptedLicenseRoutes(researchFixture(t, b)); e == nil {
		t.Fatal("malformed Mach-O accepted")
	}
}
func TestResearchMalformedConsumedEnvelopeRejected(t *testing.T) {
	if e := verifyRecoverySUPF(make([]byte, 32)); e == nil {
		t.Fatal("malformed consumed envelope accepted")
	}
}

func TestResearchMixedContainerProtectsOnlyInertChild(t *testing.T) {
	p := filepath.Join(t.TempDir(), "input.ipa")
	f, e := os.Create(p)
	if e != nil {
		t.Fatal(e)
	}
	w := zip.NewWriter(f)
	for n, b := range map[string][]byte{"Payload/Main.app/Watch/W.app/W": researchThin(4096), "Payload/Main.app/Watch/W.app/Frameworks/F.framework/F": researchThin(0)} {
		d, e := w.Create(n)
		if e != nil {
			t.Fatal(e)
		}
		d.Write(b)
	}
	w.Close()
	f.Close()
	paths, e := UnencryptedBundles(p)
	if e != nil {
		t.Fatal(e)
	}
	if len(paths) != 1 || paths[0] != "Payload/Main.app/Watch/W.app/Frameworks/F.framework/" {
		t.Fatal("encrypted parent incorrectly protected")
	}
}
