package fairplay

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"howett.net/plist"
)

func macOSTestCurrentSINF(t *testing.T, credential []byte, mode uint32) []byte {
	t.Helper()
	return macOSTestCurrentSINFWithRights(t, credential, mode, []string{"veID", "plat", "aver", "tran", "sing", "song", "tool", "medi", "mode", "hi32"})
}

func macOSTestCurrentSINFLayout(t *testing.T, credential []byte, mode uint32, short bool) []byte {
	t.Helper()
	rights := []string{"veID", "plat", "aver", "tran", "sing", "song", "tool", "medi", "mode", "hi32"}
	if short {
		rights = rights[:9]
	}
	return macOSTestCurrentSINFWithRights(t, credential, mode, rights)
}

func macOSTestCurrentSINFWithRights(t *testing.T, credential []byte, mode uint32, rightsTypes []string) []byte {
	t.Helper()
	rights := make([]byte, (len(rightsTypes)+1)*8)
	for index, typ := range rightsTypes {
		copy(rights[index*8:index*8+4], typ)
		binary.BigEndian.PutUint32(rights[index*8+4:index*8+8], uint32(index+1))
	}
	binary.BigEndian.PutUint32(rights[8*8+4:8*8+8], mode)
	copy(rights[len(rights)-8:], []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe})
	iviv := []byte{0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f}
	name := make([]byte, 256)
	copy(name, "Signal")
	header := make([]byte, 16)
	copy(header, "itun")
	binary.BigEndian.PutUint32(header[4:8], 12)
	copy(header[8:12], "vers")
	binary.BigEndian.PutUint32(header[12:16], 1)
	key := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	tmpr := []byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00}
	cleartext := append([]byte(nil), header...)
	for _, field := range []struct {
		typ     string
		payload []byte
	}{{"key ", key}, {"iviv", iviv}, {"tmpr", tmpr}, {"righ", rights}, {"name", name}} {
		cleartext = append(cleartext, macOSSINFAtom(field.typ, field.payload)...)
	}
	if len(cleartext) != 360+len(rights) {
		t.Fatalf("current private fixture has %d bytes", len(cleartext))
	}
	trailerBytes := len(cleartext) % aes.BlockSize
	private, err := macOSSINFCrypt(cleartext[:len(cleartext)-trailerBytes], credential, name, iviv, true)
	if err != nil {
		t.Fatal(err)
	}
	private = append(private, cleartext[len(cleartext)-trailerBytes:]...)
	user := make([]byte, 4)
	keyID := make([]byte, 4)
	binary.BigEndian.PutUint32(user, 0x12345678)
	binary.BigEndian.PutUint32(keyID, 2)
	var scheme []byte
	for _, field := range []struct {
		typ     string
		payload []byte
	}{{"user", user}, {"key ", keyID}, {"iviv", iviv}, {"righ", rights}, {"name", name}, {"priv", private}} {
		scheme = append(scheme, macOSSINFAtom(field.typ, field.payload)...)
	}
	root := append(macOSSINFAtom("frma", []byte("sinf")), macOSSINFAtom("schi", scheme)...)
	root = append(root, macOSSINFAtom("sign", []byte("preserved-signature"))...)
	return macOSSINFAtom("sinf", root)
}

func macOSTestCredential() []byte {
	return []byte{0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28, 0x19, 0x0a, 0xfb, 0xec, 0xdd, 0xce, 0xbf, 0xa0}
}

func macOSTestVersion2Model(t *testing.T, credential []byte) []byte {
	t.Helper()
	pack := selectorBoundModelPack(t, SINFSelector{User: 0x12345678, Key: 2})
	for index, value := range credential {
		pack[56+index] = value ^ 0x30
	}
	return pack
}

func TestMacOSSINFCryptMatchesReferenceVector(t *testing.T) {
	name := make([]byte, 256)
	copy(name, "Signal")
	iviv := []byte{0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f}
	got, err := macOSSINFCrypt(make([]byte, 16), macOSTestCredential(), name, iviv, true)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("c1daa85259037fc118c37289a069e269")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("macOS SINF AES-CBC vector = %x, want %x", got, want)
	}
}

func TestNormalizeMacOSSINF(t *testing.T) {
	credential := macOSTestCredential()
	original := macOSTestCurrentSINF(t, credential, 7)
	converted, report, err := normalizeMacOSSINF(original, credential)
	if err != nil {
		t.Fatal(err)
	}
	if report.OriginalMode != 7 || report.ConvertedMode != 0 || report.NamedRightsPreserved != 10 ||
		report.RightsSuffixRemovedBytes != 8 || !report.PrivateKeyMaterialPreserved {
		t.Fatalf("conversion report = %+v", report)
	}
	if bytes.Equal(original, converted) {
		t.Fatal("SINF conversion did not change the record")
	}
	if err := verifyMacOSSINF(converted, credential); err != nil {
		t.Fatal(err)
	}
	fields, err := parseSINFFields(converted)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 8 {
		t.Fatalf("converted SINF fields = %d, want 8", len(fields))
	}
	rights, err := macOSSINFField(converted, fields, "righ")
	if err != nil {
		t.Fatal(err)
	}
	modeAt, err := macOSSINFRightsValue(rights, "mode")
	if err != nil || binary.BigEndian.Uint32(rights[modeAt:modeAt+4]) != 0 {
		t.Fatalf("converted mode is not zero: %v", err)
	}
	crdt, err := macOSSINFField(converted, fields, "crdt")
	if err != nil || binary.BigEndian.Uint32(crdt) != 4 {
		t.Fatalf("converted crdt = %x, %v", crdt, err)
	}
	asdt, err := macOSSINFField(converted, fields, "asdt")
	if err != nil || !bytes.Equal(asdt, make([]byte, 4)) {
		t.Fatalf("converted asdt = %x, %v", asdt, err)
	}

	roots, err := sinfAtoms(converted, 0, len(converted))
	if err != nil {
		t.Fatal(err)
	}
	outer, err := sinfAtoms(converted, roots[0].start, roots[0].end)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := macOSSINFField(converted, outer, "sign")
	if err != nil || string(signature) != "preserved-signature" {
		t.Fatalf("signature = %q, %v", signature, err)
	}
}

func TestNormalizeMacOSSINFRejectsWrongCredential(t *testing.T) {
	credential := macOSTestCredential()
	fixture := macOSTestCurrentSINF(t, credential, 1)
	wrong := append([]byte(nil), credential...)
	wrong[0] ^= 0xff
	if _, _, err := normalizeMacOSSINF(fixture, wrong); err == nil || !strings.Contains(err.Error(), "credential") {
		t.Fatalf("wrong credential returned %v", err)
	}
}

func TestNormalizeShortMacOSSINF(t *testing.T) {
	credential := macOSTestCredential()
	original := macOSTestCurrentSINFLayout(t, credential, 7, true)
	converted, report, err := normalizeMacOSSINF(original, credential)
	if err != nil {
		t.Fatal(err)
	}
	if report.RightsSuffixRemovedBytes != 0 || report.NamedRightsPreserved != 9 ||
		report.OriginalMode != 7 || !report.PrivateKeyMaterialPreserved {
		t.Fatalf("short-layout report = %+v", report)
	}
	if err := verifyMacOSSINF(converted, credential); err != nil {
		t.Fatal(err)
	}
	fields, err := parseSINFFields(converted)
	if err != nil {
		t.Fatal(err)
	}
	rights, err := macOSSINFField(converted, fields, "righ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rights[72:], make([]byte, 8)) {
		t.Fatal("short-layout opaque rights suffix is not zero")
	}
}

func TestNormalizeExtendedMacOSSINF(t *testing.T) {
	credential := macOSTestCredential()
	original := macOSTestCurrentSINFWithRights(t, credential, 9, []string{
		"veID", "plat", "aver", "tran", "sing", "song", "tool", "medi", "mode", "hi32", "xtra",
	})
	converted, report, err := normalizeMacOSSINF(original, credential)
	if err != nil {
		t.Fatal(err)
	}
	if report.RightsSuffixRemovedBytes != 16 || report.NamedRightsPreserved != 10 || report.OriginalMode != 9 {
		t.Fatalf("extended-layout report = %+v", report)
	}
	if err := verifyMacOSSINF(converted, credential); err != nil {
		t.Fatal(err)
	}
	fields, err := parseSINFFields(converted)
	if err != nil {
		t.Fatal(err)
	}
	rights, err := macOSSINFField(converted, fields, "righ")
	if err != nil {
		t.Fatal(err)
	}
	if len(rights) != 80 || string(rights[72:76]) != "hi32" || bytes.Contains(rights, []byte("xtra")) {
		t.Fatalf("extended rights were not reduced structurally: %x", rights)
	}
}

func TestNormalizeMacOSSINFWithDirectEnrollmentModel(t *testing.T) {
	for _, test := range []struct {
		name                                string
		rightsAtomBytes, preserved, removed int
	}{
		{"short", 88, 9, 0},
		{"standard", 96, 10, 8},
		{"extended", 104, 10, 16},
	} {
		t.Run(test.name, func(t *testing.T) {
			innerKey := [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01}
			fixture := syntheticCurrentSINFFixture(t, 0x10203040, 2, test.rightsAtomBytes, innerKey)
			pack := selectorBoundModelPack(t, fixture.selector)
			converted, report, err := normalizeMacOSSINFWithModels(fixture.sinf, [][]byte{pack})
			if err != nil {
				t.Fatal(err)
			}
			model := syntheticLegacyModel()
			credential := make([]byte, aes.BlockSize)
			for index, value := range model.key {
				credential[index] = value ^ 0x30
			}
			defer clear(credential)
			if err := verifyMacOSSINF(converted, credential); err != nil {
				t.Fatal(err)
			}
			if report.NamedRightsPreserved != test.preserved || report.RightsSuffixRemovedBytes != test.removed {
				t.Fatalf("direct-model report = %+v", report)
			}
		})
	}
}

func TestCurrentSINFRightsGeometryIgnoresOpaqueSuffix(t *testing.T) {
	rights := make([]byte, 80)
	for index, typ := range currentSINFRequiredRights {
		copy(rights[index*8:index*8+4], typ)
	}
	copy(rights[72:], "modeABCD")
	if named, err := currentSINFRightsGeometry(rights); err != nil || named != 72 {
		t.Fatalf("opaque suffix geometry = %d, %v", named, err)
	}
	copy(rights[8:12], "veID")
	if _, err := currentSINFRightsGeometry(rights); err == nil {
		t.Fatal("duplicate named right was accepted")
	}
}

func writeMacOSTestIPA(t *testing.T, name string, members map[string][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for member, value := range members {
		target, createErr := writer.Create(member)
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, writeErr := target.Write(value); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func readMacOSTestZIP(t *testing.T, path string) map[string][]byte {
	t.Helper()
	archive, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	result := make(map[string][]byte)
	for _, file := range archive.File {
		value, readErr := zipBytes(file)
		if readErr != nil {
			t.Fatal(readErr)
		}
		result[file.Name] = value
	}
	return result
}

func TestPrepareMacOSIPAMultipleSINFs(t *testing.T) {
	credential := macOSTestCredential()
	mainSINF := macOSTestCurrentSINF(t, credential, 1)
	watchSINF := macOSTestCurrentSINF(t, credential, 2)
	executable := []byte("encrypted-mach-o-is-byte-identical")
	input := writeMacOSTestIPA(t, "Signal.ipa", map[string][]byte{
		"Payload/Signal.app/Signal":                                         executable,
		"Payload/Signal.app/SC_Info/Signal.sinf":                            mainSINF,
		"Payload/Signal.app/Watch/SignalWatch.app/SC_Info/SignalWatch.sinf": watchSINF,
	})
	credentialPath := filepath.Join(t.TempDir(), "credential.bin")
	if err := os.WriteFile(credentialPath, credential, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "Signal.macos.ipa")
	result, err := PrepareMacOSIPA(MacOSPrepareOptions{
		InputPath: input, OutputPath: output, CredentialPath: credentialPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Schema != "unfairplay-macos-preparation-v1" || len(result.Records) != 2 ||
		result.MachOModified || len(result.InputSHA256) != 64 || len(result.OutputSHA256) != 64 {
		t.Fatalf("preparation result = %+v", result)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode = %v, %v", info.Mode(), err)
	}
	members := readMacOSTestZIP(t, output)
	if !bytes.Equal(members["Payload/Signal.app/Signal"], executable) {
		t.Fatal("conversion changed the executable")
	}
	for _, name := range []string{
		"Payload/Signal.app/SC_Info/Signal.sinf",
		"Payload/Signal.app/Watch/SignalWatch.app/SC_Info/SignalWatch.sinf",
	} {
		if err := verifyMacOSSINF(members[name], credential); err != nil {
			t.Fatalf("verify %s: %v", name, err)
		}
	}
	if _, err := PrepareMacOSIPA(MacOSPrepareOptions{
		InputPath: input, OutputPath: output, CredentialPath: credentialPath,
	}); err == nil || !strings.Contains(err.Error(), "refusing to replace") {
		t.Fatalf("existing output returned %v", err)
	}
}

func TestPrepareMacOSIPARejectsUnsafeCredential(t *testing.T) {
	credential := macOSTestCredential()
	input := writeMacOSTestIPA(t, "App.ipa", map[string][]byte{
		"Payload/App.app/SC_Info/App.sinf": macOSTestCurrentSINF(t, credential, 1),
	})
	credentialPath := filepath.Join(t.TempDir(), "credential.bin")
	if err := os.WriteFile(credentialPath, credential, 0o644); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "App.macos.ipa")
	_, err := PrepareMacOSIPA(MacOSPrepareOptions{
		InputPath: input, OutputPath: output, CredentialPath: credentialPath,
	})
	if err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("unsafe credential returned %v", err)
	}
	if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
		t.Fatalf("unsafe conversion published output: %v", statErr)
	}
}

func TestPrepareMacOSIPAWithEnrollmentModel(t *testing.T) {
	credential := macOSTestCredential()
	input := writeMacOSTestIPA(t, "App.ipa", map[string][]byte{
		"Payload/App.app/App":              []byte("encrypted"),
		"Payload/App.app/SC_Info/App.sinf": macOSTestCurrentSINF(t, credential, 3),
	})
	modelPath := filepath.Join(t.TempDir(), "fairplay-enrollment.bin")
	if err := os.WriteFile(modelPath, macOSTestVersion2Model(t, credential), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "App.macos.ipa")
	result, err := PrepareMacOSIPA(MacOSPrepareOptions{
		InputPath: input, OutputPath: output, ModelPath: modelPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 1 || result.Records[0].OriginalMode != 3 {
		t.Fatalf("model conversion result = %+v", result)
	}
	members := readMacOSTestZIP(t, output)
	if err := verifyMacOSSINF(members["Payload/App.app/SC_Info/App.sinf"], credential); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareMacOSIPAReplicatesManifestSINFPaths(t *testing.T) {
	credential := macOSTestCredential()
	manifest, err := plist.Marshal(macOSSINFManifest{
		SINFPaths: []string{"SC_Info/App.sinf"},
		SINFReplicationPaths: []string{
			"Frameworks/Library.framework/SC_Info/Library.sinf",
			"PlugIns/Widget.appex/SC_Info/Widget.sinf",
			"SC_Info/App.sinf",
		},
	}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	input := writeMacOSTestIPA(t, "App.ipa", map[string][]byte{
		"Payload/App.app/App": []byte("encrypted-main"),
		"Payload/App.app/Frameworks/Library.framework/Library": []byte("encrypted-framework"),
		"Payload/App.app/SC_Info/App.sinf":                     macOSTestCurrentSINF(t, credential, 4),
		"Payload/App.app/SC_Info/Manifest.plist":               manifest,
	})
	modelPath := filepath.Join(t.TempDir(), "fairplay-enrollment.bin")
	if err := os.WriteFile(modelPath, macOSTestVersion2Model(t, credential), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "App.macos.ipa")
	result, err := PrepareMacOSIPA(MacOSPrepareOptions{
		InputPath: input, OutputPath: output, ModelPath: modelPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 3 {
		t.Fatalf("converted SINF records = %d, want 3", len(result.Records))
	}
	members := readMacOSTestZIP(t, output)
	source := members["Payload/App.app/SC_Info/App.sinf"]
	for _, target := range []string{
		"Payload/App.app/Frameworks/Library.framework/SC_Info/Library.sinf",
		"Payload/App.app/PlugIns/Widget.appex/SC_Info/Widget.sinf",
	} {
		if !bytes.Equal(members[target], source) {
			t.Fatalf("replicated SINF %s differs from source", target)
		}
	}
	if !bytes.Equal(members["Payload/App.app/Frameworks/Library.framework/Library"], []byte("encrypted-framework")) {
		t.Fatal("SINF replication changed the framework executable")
	}
	replicated := 0
	for _, report := range result.Records {
		if report.ReplicatedFrom != "" {
			replicated++
		}
	}
	if replicated != 2 {
		t.Fatalf("replicated reports = %d, want 2", replicated)
	}
}

func TestPrepareMacOSIPAMultipleManifestSources(t *testing.T) {
	credential := macOSTestCredential()
	sourceA := macOSTestCurrentSINF(t, credential, 3)
	sourceB := macOSTestCurrentSINF(t, credential, 4)
	manifest, err := plist.Marshal(macOSSINFManifest{
		SINFPaths: []string{"SC_Info/A.sinf", "SC_Info/B.sinf"},
		SINFReplicationPaths: []string{
			"PlugIns/A.appex/SC_Info/A.sinf",
			"PlugIns/B.appex/SC_Info/B.sinf",
		},
	}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	input := writeMacOSTestIPA(t, "App.ipa", map[string][]byte{
		"Payload/App.app/SC_Info/A.sinf":                 sourceA,
		"Payload/App.app/SC_Info/B.sinf":                 sourceB,
		"Payload/App.app/PlugIns/A.appex/SC_Info/A.sinf": sourceA,
		"Payload/App.app/PlugIns/B.appex/SC_Info/B.sinf": sourceB,
		"Payload/App.app/SC_Info/Manifest.plist":         manifest,
	})
	modelPath := filepath.Join(t.TempDir(), "fairplay-enrollment.bin")
	if err := os.WriteFile(modelPath, macOSTestVersion2Model(t, credential), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "App.macos.ipa")
	result, err := PrepareMacOSIPA(MacOSPrepareOptions{InputPath: input, OutputPath: output, ModelPath: modelPath})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 4 {
		t.Fatalf("converted SINF records = %d, want 4", len(result.Records))
	}
	members := readMacOSTestZIP(t, output)
	for _, pair := range [][2]string{
		{"Payload/App.app/SC_Info/A.sinf", "Payload/App.app/PlugIns/A.appex/SC_Info/A.sinf"},
		{"Payload/App.app/SC_Info/B.sinf", "Payload/App.app/PlugIns/B.appex/SC_Info/B.sinf"},
	} {
		if !bytes.Equal(members[pair[0]], members[pair[1]]) {
			t.Fatalf("converted replica %q differs from %q", pair[1], pair[0])
		}
		if err := verifyMacOSSINF(members[pair[1]], credential); err != nil {
			t.Fatal(err)
		}
	}
}

func TestExternalMacOSCredentialFromEnrollmentModel(t *testing.T) {
	modelPath := os.Getenv("UNFAIRPLAY_MACOS_CREDENTIAL_MODEL")
	sinfPath := os.Getenv("UNFAIRPLAY_MACOS_CREDENTIAL_SINF")
	ipaPath := os.Getenv("UNFAIRPLAY_MACOS_CREDENTIAL_IPA")
	if modelPath == "" || sinfPath == "" && ipaPath == "" {
		t.Skip("private macOS credential fixture is not configured")
	}
	pack, err := os.ReadFile(modelPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pack)
	var sinf []byte
	if sinfPath != "" {
		sinf, err = os.ReadFile(sinfPath)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		archive, openErr := zip.OpenReader(ipaPath)
		if openErr != nil {
			t.Fatal(openErr)
		}
		defer archive.Close()
		for _, file := range archive.File {
			if strings.Contains(file.Name, "/SC_Info/") && strings.HasSuffix(strings.ToLower(file.Name), ".sinf") {
				if sinf != nil {
					t.Fatal("private IPA fixture contains more than one SINF")
				}
				sinf, err = zipBytes(file)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		if sinf == nil {
			t.Fatal("private IPA fixture contains no SINF")
		}
	}
	defer clear(sinf)
	converted, _, err := normalizeMacOSSINFWithModels(sinf, [][]byte{pack})
	if err != nil {
		t.Fatal(err)
	}
	clear(converted)
}
