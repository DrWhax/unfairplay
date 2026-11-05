package fairplay

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func multiSINFImage(t *testing.T, logical [16]byte, word uint32) ([]byte, []byte, []byte) {
	t.Helper()
	blob, _ := signedPreEncryptionAuditFixture(t, pageBytes, pageBytes, 12, 2)
	clear(blob[:pageBytes])
	le := func(at int, value uint32) { binary.LittleEndian.PutUint32(blob[at:], value) }
	le(0, mhMagic64)
	le(4, cpuTypeARM64)
	le(12, 2)
	le(16, 2)
	le(20, 40)
	le(32, lcEncryptionInfo64)
	le(36, 24)
	le(40, pageBytes)
	le(44, pageBytes)
	le(48, 1)
	le(56, lcCodeSignature)
	le(60, 16)
	le(64, 2*pageBytes)
	le(68, uint32(len(blob)-2*pageBytes))

	plain := make([]byte, pageBytes)
	for offset := 0; offset < len(plain); offset += 4 {
		binary.LittleEndian.PutUint32(plain[offset:], word)
	}
	var record [32]byte
	for index := range record {
		record[index] = byte(index + 1)
	}
	deriver := newPageKeyDeriver(appMaskFromLogicalKey(logical))
	key := deriver.pageKey(record[:16], pageBytes)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	copy(blob[pageBytes:2*pageBytes], plain)
	setSyntheticPreEncryptionHashes(t, blob, machoLayout{signatureOffset: 2 * pageBytes})
	cipher.NewCBCEncrypter(block, record[16:]).CryptBlocks(blob[pageBytes:2*pageBytes], plain)
	directory := blob[2*pageBytes+20:]
	for slot := 0; slot < 2; slot++ {
		hash, err := hashCodePage(2, blob[slot*pageBytes:(slot+1)*pageBytes])
		if err != nil {
			t.Fatal(err)
		}
		copy(directory[96+slot*32:], hash)
	}
	supf := make([]byte, 60)
	supf[0] = 5
	be := func(at int, value uint32) { binary.BigEndian.PutUint32(supf[at:], value) }
	be(4, 52)
	be(8, 1)
	be(12, 44)
	be(16, cpuTypeARM64)
	be(24, 1)
	copy(supf[28:], record[:])
	return blob, supf, plain
}

func writeMultiSINFArchive(t *testing.T, name string, members map[string][]byte) {
	t.Helper()
	file, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	order := []string{
		"Payload/Test.app/Test",
		"Payload/Test.app/SC_Info/Test.sinf",
		"Payload/Test.app/SC_Info/Test.v5.supf",
		"Payload/Test.app/keep.txt",
		"Payload/Test.app/PlugIns/Widget.appex/Test",
		"Payload/Test.app/PlugIns/Widget.appex/SC_Info/Test.sinf",
		"Payload/Test.app/PlugIns/Widget.appex/SC_Info/Test.v5.supf",
	}
	for _, member := range order {
		data, ok := members[member]
		if !ok {
			continue
		}
		writer, err := archive.Create(member)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDecryptMultipleSINFs(t *testing.T) {
	directory := t.TempDir()
	mainPath := "Payload/Test.app/Test"
	widgetPath := "Payload/Test.app/PlugIns/Widget.appex/Test"
	mainFixture := syntheticCurrentSINFFixture(t, 42, 7, 88, [16]byte{1, 2, 3})
	widgetFixture := syntheticCurrentSINFFixture(t, 42, 8, 88, [16]byte{9, 8, 7})
	mainBlob, mainSUPF, mainPlain := multiSINFImage(t, mainFixture.logical, 0xd503201f)
	widgetBlob, widgetSUPF, widgetPlain := multiSINFImage(t, widgetFixture.logical, 0xd65f03c0)
	members := map[string][]byte{
		mainPath: mainBlob, adjacentSINF(mainPath): mainFixture.sinf,
		"Payload/Test.app/SC_Info/Test.v5.supf": mainSUPF,
		widgetPath:                              widgetBlob, adjacentSINF(widgetPath): widgetFixture.sinf,
		"Payload/Test.app/PlugIns/Widget.appex/SC_Info/Test.v5.supf": widgetSUPF,
		"Payload/Test.app/keep.txt":                                  []byte("unchanged"),
	}
	input := filepath.Join(directory, "App.ipa")
	writeMultiSINFArchive(t, input, members)
	models := filepath.Join(directory, "models")
	if err := os.Mkdir(models, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, selector := range map[string]SINFSelector{
		"main.bin": mainFixture.selector, "widget.bin": widgetFixture.selector,
	} {
		if err := os.WriteFile(filepath.Join(models, name), selectorBoundModelPack(t, selector), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	output, reportPath := filepath.Join(directory, "out.ipa"), filepath.Join(directory, "out.json")
	result, err := DecryptIPA(DecryptOptions{
		InputPath: input, OutputPath: output, ReportPath: reportPath, ModelPath: models,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.EncryptedImages != 2 || result.DecryptedPages != 2 || result.LogicalKeySHA256 != "" || len(result.LogicalKeySHA256BySINF) != 2 {
		t.Fatalf("incorrect multi-license result: %+v", result)
	}
	if result.LogicalKeySHA256BySINF[adjacentSINF(mainPath)] == result.LogicalKeySHA256BySINF[adjacentSINF(widgetPath)] {
		t.Fatal("different logical keys were conflated")
	}

	archive, err := zip.OpenReader(output)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	for _, file := range archive.File {
		got, err := zipBytes(file)
		if err != nil {
			t.Fatal(err)
		}
		want := members[file.Name]
		if file.Name == mainPath || file.Name == widgetPath {
			want = append([]byte(nil), want...)
			binary.LittleEndian.PutUint32(want[48:], 0)
			plain := mainPlain
			if file.Name == widgetPath {
				plain = widgetPlain
			}
			copy(want[pageBytes:2*pageBytes], plain)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("wrong bytes for %s", file.Name)
		}
	}
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report decryptionReport
	if err := json.Unmarshal(reportData, &report); err != nil {
		t.Fatal(err)
	}
	if !report.Complete || len(report.Licenses) != 2 || len(report.Images) != 2 {
		t.Fatalf("incomplete report: %+v", report)
	}
	if report.Schema != "unfairplay-decryption-v2" || !report.PlaintextVerified {
		t.Fatalf("wrong report schema or plaintext coverage: %+v", report)
	}
	var wire struct {
		Images []map[string]json.RawMessage `json:"images"`
	}
	if err := json.Unmarshal(reportData, &wire); err != nil {
		t.Fatal(err)
	}
	for _, image := range wire.Images {
		if _, old := image["first_page_audit"]; old {
			t.Fatal("v2 report retained obsolete instruction audit")
		}
		if len(image["pre_encryption_code_directories"]) == 0 {
			t.Fatal("v2 report omitted plaintext hash coverage")
		}
	}
	for _, image := range report.Images {
		if image.SINFMember != adjacentSINF(image.Member) {
			t.Fatalf("wrong SINF for %s", image.Member)
		}
	}
	doctor := DoctorFairPlay("", input, models)
	if !doctor.DecryptReady || len(doctor.CompatibleModelsBySINF) != 2 {
		t.Fatalf("doctor rejected valid multi-license IPA: %v", doctor.Errors)
	}
}

func TestMultipleSINFsFailBeforePublishing(t *testing.T) {
	directory := t.TempDir()
	mainPath := "Payload/Test.app/Test"
	widgetPath := "Payload/Test.app/PlugIns/Widget.appex/Test"
	fixture := syntheticCurrentSINFFixture(t, 42, 7, 88, [16]byte{1, 2, 3})
	mainBlob, mainSUPF, _ := multiSINFImage(t, fixture.logical, 0xd503201f)
	widgetBlob, widgetSUPF, _ := multiSINFImage(t, fixture.logical, 0xd65f03c0)
	members := map[string][]byte{
		mainPath:                                mainBlob,
		"Payload/Test.app/SC_Info/Test.v5.supf": mainSUPF,
		widgetPath:                              widgetBlob,
		"Payload/Test.app/PlugIns/Widget.appex/SC_Info/Test.v5.supf": widgetSUPF,
	}
	input := filepath.Join(directory, "App.ipa")
	writeMultiSINFArchive(t, input, members)
	output, report := filepath.Join(directory, "out.ipa"), filepath.Join(directory, "out.json")
	if err := os.WriteFile(output, []byte("existing output"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(report, []byte("existing report"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := DecryptIPA(DecryptOptions{InputPath: input, OutputPath: output, ReportPath: report, Force: true})
	if err == nil {
		t.Fatal("accepted an encrypted executable without an adjacent SINF")
	}
	for path, want := range map[string]string{output: "existing output", report: "existing report"} {
		got, readErr := os.ReadFile(path)
		if readErr != nil || string(got) != want {
			t.Fatalf("published partial output at %s", path)
		}
	}
}

func TestAdjacentSINFTopLevel(t *testing.T) {
	if got := adjacentSINF("App"); got != "SC_Info/App.sinf" {
		t.Fatalf("top-level license path: %s", got)
	}
}

func TestSINFMappingRequiresExplicitManifest(t *testing.T) {
	const main = "Payload/Test.app/SC_Info/Test.sinf"
	const target = "Payload/Test.app/PlugIns/Widget.appex/SC_Info/Widget.sinf"
	const manifest = "Payload/Test.app/SC_Info/Manifest.plist"
	entries := map[string][]byte{main: []byte("synthetic license")}
	mapping, err := buildSINFAssociations(syntheticLicenseFiles(t, entries))
	if err != nil || len(mapping) != 0 {
		t.Fatalf("unexpected implicit association: %v, %v", mapping, err)
	}
	entries[manifest] = syntheticLicenseManifest(t, []string{"SC_Info/Test.sinf"}, []string{"PlugIns/Widget.appex/SC_Info/Widget.sinf"})
	mapping, err = buildSINFAssociations(syntheticLicenseFiles(t, entries))
	if err != nil || mapping[target] != main || len(mapping) != 1 {
		t.Fatalf("explicit association: %v, %v", mapping, err)
	}
}
