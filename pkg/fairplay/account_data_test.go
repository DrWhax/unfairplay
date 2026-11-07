package fairplay

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"howett.net/plist"
)

const syntheticStoreMetadata = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>apple-id</key><string>buyer@example.com</string>
<key>userName</key><string>buyer@example.com</string>
<key>itemName</key><string>Test</string>
<key>bundleShortVersionString</key><string>1.0</string>
<key>com.apple.iTunesStore.downloadInfo</key><dict>
<key>accountInfo</key><dict><key>AppleID</key><string>buyer@example.com</string><key>DSPersonID</key><integer>42</integer></dict>
<key>purchaseDate</key><string>2026-01-01T00:00:00Z</string>
</dict>
</dict></plist>`

func writeOrderedArchive(t *testing.T, name string, members []string, data map[string][]byte) {
	t.Helper()
	file, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	archive := zip.NewWriter(file)
	for _, member := range members {
		writer, err := archive.Create(member)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data[member]); err != nil {
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

const (
	stripMainPath   = "Payload/Test.app/Test"
	stripWidgetPath = "Payload/Test.app/PlugIns/Widget.appex/Test"
)

type stripFixture struct {
	input, models string
	members       []string
	data          map[string][]byte
	plain         map[string][]byte
}

// newStripFixture builds the two-SINF app and extension IPA. metadata, when
// not nil, is stored as iTunesMetadata.plist.
func newStripFixture(t *testing.T, metadata []byte) stripFixture {
	t.Helper()
	directory := t.TempDir()
	mainFixture := syntheticCurrentSINFFixture(t, 42, 7, 88, [16]byte{1, 2, 3})
	widgetFixture := syntheticCurrentSINFFixture(t, 42, 8, 88, [16]byte{9, 8, 7})
	mainBlob, mainSUPF, mainPlain := multiSINFImage(t, mainFixture.logical, 0xd503201f)
	widgetBlob, widgetSUPF, widgetPlain := multiSINFImage(t, widgetFixture.logical, 0xd65f03c0)
	f := stripFixture{
		input: filepath.Join(directory, "App.ipa"), models: filepath.Join(directory, "models"),
		data: map[string][]byte{
			stripMainPath: mainBlob, adjacentSINF(stripMainPath): mainFixture.sinf,
			"Payload/Test.app/SC_Info/Test.v5.supf": mainSUPF,
			"Payload/Test.app/keep.txt":             []byte("unchanged"),
			stripWidgetPath:                         widgetBlob, adjacentSINF(stripWidgetPath): widgetFixture.sinf,
			"Payload/Test.app/PlugIns/Widget.appex/SC_Info/Test.v5.supf": widgetSUPF,
		},
		plain: map[string][]byte{stripMainPath: mainPlain, stripWidgetPath: widgetPlain},
	}
	if metadata != nil {
		f.members = append(f.members, storeMetadataMember)
		f.data[storeMetadataMember] = metadata
	}
	f.members = append(f.members,
		stripMainPath, adjacentSINF(stripMainPath), "Payload/Test.app/SC_Info/Test.v5.supf",
		"Payload/Test.app/keep.txt",
		stripWidgetPath, adjacentSINF(stripWidgetPath), "Payload/Test.app/PlugIns/Widget.appex/SC_Info/Test.v5.supf",
	)
	writeOrderedArchive(t, f.input, f.members, f.data)
	if err := os.Mkdir(f.models, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, selector := range map[string]SINFSelector{
		"main.bin": mainFixture.selector, "widget.bin": widgetFixture.selector,
	} {
		if err := os.WriteFile(filepath.Join(f.models, name), selectorBoundModelPack(t, selector), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// decryptStripped decrypts with StripAccountData and returns the result, the
// output members, and the report.
func (f stripFixture) decryptStripped(t *testing.T) (DecryptResult, map[string][]byte, []string, decryptionReport) {
	t.Helper()
	directory := t.TempDir()
	output, reportPath := filepath.Join(directory, "out.ipa"), filepath.Join(directory, "out.json")
	result, err := DecryptIPA(DecryptOptions{
		InputPath: f.input, OutputPath: output, ReportPath: reportPath, ModelPath: f.models, StripAccountData: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	archive, err := zip.OpenReader(output)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	members := map[string][]byte{}
	var names []string
	for _, file := range archive.File {
		got, err := zipBytes(file)
		if err != nil {
			t.Fatal(err)
		}
		members[file.Name] = got
		names = append(names, file.Name)
	}
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report decryptionReport
	if err := json.Unmarshal(reportData, &report); err != nil {
		t.Fatal(err)
	}
	return result, members, names, report
}

// checkNonMetadataMembers verifies that licenses are gone and every other
// member is the decrypted or original bytes.
func (f stripFixture) checkNonMetadataMembers(t *testing.T, members map[string][]byte, names []string) {
	t.Helper()
	var want []string
	if _, ok := f.data[storeMetadataMember]; ok {
		want = append(want, storeMetadataMember)
	}
	want = append(want, stripMainPath, "Payload/Test.app/keep.txt", stripWidgetPath)
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("members %v, want %v", names, want)
	}
	for name, got := range members {
		switch name {
		case storeMetadataMember:
		case stripMainPath, stripWidgetPath:
			expected := append([]byte(nil), f.data[name]...)
			binary.LittleEndian.PutUint32(expected[48:], 0)
			copy(expected[pageBytes:2*pageBytes], f.plain[name])
			if !bytes.Equal(got, expected) {
				t.Fatalf("wrong decrypted bytes for %s", name)
			}
		default:
			if !bytes.Equal(got, f.data[name]) {
				t.Fatalf("wrong bytes for %s", name)
			}
		}
	}
}

func checkScrubbedMetadata(t *testing.T, data []byte) {
	t.Helper()
	if bytes.Contains(data, []byte("buyer@example.com")) {
		t.Fatalf("Apple ID kept in metadata:\n%s", data)
	}
	var metadata map[string]any
	if _, err := plist.Unmarshal(data, &metadata); err != nil {
		t.Fatal(err)
	}
	download := metadata["com.apple.iTunesStore.downloadInfo"].(map[string]any)
	if metadata["itemName"] != "Test" || metadata["bundleShortVersionString"] != "1.0" ||
		download["accountInfo"] != nil || download["purchaseDate"] == nil {
		t.Fatalf("metadata %v", metadata)
	}
}

func checkAccountData(t *testing.T, result DecryptResult, report decryptionReport, licenses, metadata int) {
	t.Helper()
	if !result.AccountDataStripped || result.RemovedLicenseFiles != licenses || result.RemovedMetadataFields != metadata {
		t.Fatalf("result %+v, want stripped with %d license files and %d metadata fields", result, licenses, metadata)
	}
	want := accountDataReport{Stripped: true, RemovedLicenseFiles: licenses, RemovedMetadataFields: metadata}
	if !report.Complete || report.AccountData == nil || *report.AccountData != want {
		t.Fatalf("report account data %+v, want %+v", report.AccountData, want)
	}
}

func TestDecryptStripAccountData(t *testing.T) {
	f := newStripFixture(t, []byte(syntheticStoreMetadata))
	result, members, names, report := f.decryptStripped(t)
	if result.EncryptedImages != 2 {
		t.Fatalf("result %+v", result)
	}
	checkAccountData(t, result, report, 4, 3)
	f.checkNonMetadataMembers(t, members, names)
	checkScrubbedMetadata(t, members[storeMetadataMember])
	if !bytes.HasPrefix(members[storeMetadataMember], []byte("<?xml")) {
		t.Fatal("XML metadata was not kept as XML")
	}

	// Without the option the output keeps every member and the report has
	// no account data section.
	directory := t.TempDir()
	plainOutput, plainReport := filepath.Join(directory, "keep.ipa"), filepath.Join(directory, "keep.json")
	plainResult, err := DecryptIPA(DecryptOptions{
		InputPath: f.input, OutputPath: plainOutput, ReportPath: plainReport, ModelPath: f.models,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plainResult.AccountDataStripped || plainResult.RemovedLicenseFiles != 0 {
		t.Fatalf("default result %+v", plainResult)
	}
	kept, err := zip.OpenReader(plainOutput)
	if err != nil {
		t.Fatal(err)
	}
	defer kept.Close()
	if len(kept.File) != len(f.members) {
		t.Fatalf("default output has %d members, want %d", len(kept.File), len(f.members))
	}
	reportData, err := os.ReadFile(plainReport)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(reportData, []byte("account_data")) {
		t.Fatal("default report has an account data section")
	}
}

func TestDecryptStripAccountDataBinaryMetadata(t *testing.T) {
	var metadata map[string]any
	if _, err := plist.Unmarshal([]byte(syntheticStoreMetadata), &metadata); err != nil {
		t.Fatal(err)
	}
	binaryMetadata, err := plist.Marshal(metadata, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	f := newStripFixture(t, binaryMetadata)
	result, members, names, report := f.decryptStripped(t)
	checkAccountData(t, result, report, 4, 3)
	f.checkNonMetadataMembers(t, members, names)
	got := members[storeMetadataMember]
	if !bytes.HasPrefix(got, []byte("bplist00")) {
		t.Fatalf("binary metadata was not kept binary: %q", got[:min(len(got), 16)])
	}
	checkScrubbedMetadata(t, got)
}

// The closest end-to-end control: no iTunesMetadata.plist. A decryptable
// IPA always has SC_Info, because every encrypted image needs its SINF there.
func TestDecryptStripAccountDataWithoutMetadata(t *testing.T) {
	f := newStripFixture(t, nil)
	result, members, names, report := f.decryptStripped(t)
	checkAccountData(t, result, report, 4, 0)
	f.checkNonMetadataMembers(t, members, names)
}

// Control with neither iTunesMetadata.plist nor SC_Info: nothing is removed,
// yet the result and report still state that stripping was requested, with
// explicit zero counts.
func TestAccountDataStripperNothingToRemove(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "in.ipa")
	members := []string{"Payload/Test.app/Test", "Payload/Test.app/Info.plist"}
	writeOrderedArchive(t, input, members, map[string][]byte{
		"Payload/Test.app/Test": []byte("binary"), "Payload/Test.app/Info.plist": []byte("info"),
	})
	source, err := zip.OpenReader(input)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	stripper := &accountDataStripper{}
	for _, file := range source.File {
		handled, err := stripper.write(writer, file)
		if err != nil {
			t.Fatal(err)
		}
		if handled {
			t.Fatalf("%s was treated as account data", file.Name)
		}
	}
	section := stripper.report()
	if section == nil || *section != (accountDataReport{Stripped: true}) {
		t.Fatalf("report section %+v", section)
	}
	encoded, err := json.Marshal(decryptionReport{AccountData: section})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"account_data":{"stripped":true,"removed_license_files":0,"removed_metadata_fields":0}`)) {
		t.Fatalf("zero counts are not explicit: %s", encoded)
	}
	encoded, err = json.Marshal(DecryptResult{AccountDataStripped: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"AccountDataStripped":true,"RemovedLicenseFiles":0,"RemovedMetadataFields":0`)) {
		t.Fatalf("result zero counts are not explicit: %s", encoded)
	}
	var nothing *accountDataStripper
	if nothing.report() != nil {
		t.Fatal("report section written without a stripping request")
	}
}

func TestScrubStoreMetadataRejectsOversizedMetadata(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "in.ipa")
	large := bytes.Repeat([]byte(" "), maxStoreMetadataBytes+1)
	writeOrderedArchive(t, input, []string{storeMetadataMember}, map[string][]byte{storeMetadataMember: large})
	source, err := zip.OpenReader(input)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	_, _, err = scrubStoreMetadata(source.File[0])
	if err == nil || !strings.Contains(err.Error(), "exceeds the 16777216-byte metadata limit") {
		t.Fatalf("got %v, want a size limit error", err)
	}

	// A header that understates the size passes the explicit check, but
	// archive/zip rejects reading past the declared size, so it still fails
	// closed without returning metadata.
	source.File[0].UncompressedSize64 = 10
	data, _, err := scrubStoreMetadata(source.File[0])
	if err == nil || data != nil {
		t.Fatalf("understated header: got %d bytes, err %v; want an error", len(data), err)
	}
}

func TestIsLicenseMember(t *testing.T) {
	for name, want := range map[string]bool{
		"Payload/A.app/SC_Info/":                         true,
		"Payload/A.app/SC_Info/A.sinf":                   true,
		"Payload/A.app/PlugIns/B.appex/sc_info/B.supf":   true,
		"Payload/A.app/Watch/W.app/SC_Info/W.sinf":       true,
		"Payload/A.app/SC_Information.txt":               false,
		"Payload/A.app/Frameworks/SC_InfoKit.framework/": false,
	} {
		if got := isLicenseMember(name); got != want {
			t.Errorf("isLicenseMember(%q) = %v", name, got)
		}
	}
}
