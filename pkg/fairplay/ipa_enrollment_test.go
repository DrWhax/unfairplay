package fairplay

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestIPAEnrollmentSelection(t *testing.T) {
	mainPath, widgetPath := "Payload/Test.app/Test", "Payload/Test.app/PlugIns/Widget.appex/Test"
	main := syntheticCurrentSINFFixture(t, 42, 7, 88, [16]byte{1, 2, 3})
	widget := syntheticCurrentSINFFixture(t, 42, 7, 88, [16]byte{9, 8, 7})
	mainBlob, mainSUPF, _ := multiSINFImage(t, main.logical, 0xd503201f)
	widgetBlob, widgetSUPF, _ := multiSINFImage(t, widget.logical, 0xd65f03c0)
	members := map[string][]byte{
		mainPath: mainBlob, adjacentSINF(mainPath): main.sinf, "Payload/Test.app/SC_Info/Test.v5.supf": mainSUPF,
		widgetPath: widgetBlob, adjacentSINF(widgetPath): widget.sinf, "Payload/Test.app/PlugIns/Widget.appex/SC_Info/Test.v5.supf": widgetSUPF,
	}
	read := func() (IPAEnrollmentInputs, error) {
		name := filepath.Join(t.TempDir(), "app.ipa")
		writeMultiSINFArchive(t, name, members)
		return ReadIPAEnrollmentInputs(name)
	}
	got, err := read()
	if err != nil {
		t.Fatal(err)
	}
	// PlugIns sorts before SC_Info; this choice is independent of ZIP order.
	if got.Selector != main.selector || !bytes.Equal(got.Files["selected.sinf"], widget.sinf) || len(got.Files) != 3 {
		t.Fatal("incorrect deterministic IPA inputs")
	}
	got.Clear()
	if len(got.Files) != 0 {
		t.Fatal("licenses not cleared")
	}
	other := syntheticCurrentSINFFixture(t, 42, 8, 88, [16]byte{9})
	members[adjacentSINF(widgetPath)] = other.sinf
	if input, err := read(); err == nil || len(input.Files) != 0 {
		t.Fatal("accepted multiple selectors or retained failed inputs")
	}
	members[adjacentSINF(widgetPath)] = []byte("malformed")
	if _, err := read(); err == nil {
		t.Fatal("accepted malformed SINF")
	}
	delete(members, adjacentSINF(widgetPath))
	if _, err := read(); err == nil {
		t.Fatal("accepted missing SINF")
	}
	members[adjacentSINF(widgetPath)] = widget.sinf
	members["Payload/Test.app/PlugIns/Widget.appex/SC_Info/Test.v5.supf"] = []byte{5}
	if _, err := read(); err == nil {
		t.Fatal("accepted malformed selected key class")
	}
}

func TestIPAEnrollmentLicenseBounds(t *testing.T) {
	name := filepath.Join(t.TempDir(), "oversized.ipa")
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	header := &zip.FileHeader{Name: "Payload/Test.app/SC_Info/Test.sinf", Method: zip.Store, UncompressedSize64: maximumEnrollmentLicenseBytes + 1}
	if _, err := w.CreateRaw(header); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadIPAEnrollmentInputs(name); err == nil {
		t.Fatal("accepted oversized license")
	}
	if _, err := boundedEnrollmentMember(nil); err == nil {
		t.Fatal("accepted missing license")
	}
}
