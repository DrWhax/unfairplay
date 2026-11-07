package fairplay

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"strings"
	"testing"

	"howett.net/plist"
)

func syntheticLicenseFiles(t *testing.T, entries map[string][]byte) map[string]*zip.File {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, data := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]*zip.File, len(r.File))
	for _, f := range r.File {
		files[f.Name] = f
	}
	return files
}
func syntheticLicenseManifest(t *testing.T, source []string, replicas []string) []byte {
	t.Helper()
	data, err := plist.Marshal(macOSSINFManifest{SINFPaths: source, SINFReplicationPaths: replicas}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSINFManifestAssociations(t *testing.T) {
	const root = "Payload/A.app/"
	const source = root + "SC_Info/A.sinf"
	const target = root + "PlugIns/B.appex/SC_Info/B.sinf"
	manifest := root + "SC_Info/Manifest.plist"
	sourcePath := "SC_Info/A.sinf"
	targetPath := "PlugIns/B.appex/SC_Info/B.sinf"
	for _, tc := range []struct {
		name              string
		sources, replicas []string
		targetData        []byte
		includeTarget     bool
		wantErr           bool
	}{
		{"missing replica resolves to source", []string{sourcePath}, []string{targetPath}, nil, false, false},
		{"identical replica", []string{sourcePath}, []string{targetPath}, []byte("source"), true, false},
		{"different existing replica rejected", []string{sourcePath}, []string{targetPath}, []byte("other"), true, true},
		{"duplicate target rejected", []string{sourcePath}, []string{targetPath, targetPath}, nil, false, true},
		{"duplicate source rejected", []string{sourcePath, sourcePath}, []string{targetPath}, nil, false, true},
		{"traversal rejected", []string{sourcePath}, []string{"../SC_Info/B.sinf"}, nil, false, true},
		{"absolute rejected", []string{sourcePath}, []string{"/SC_Info/B.sinf"}, nil, false, true},
		{"backslash rejected", []string{sourcePath}, []string{"SC_Info\\B.sinf"}, nil, false, true},
		{"noncanonical path rejected", []string{sourcePath}, []string{"PlugIns/./B.appex/SC_Info/B.sinf"}, nil, false, true},
		{"non SINF rejected", []string{sourcePath}, []string{"SC_Info/B.supf"}, nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := map[string][]byte{source: []byte("source"), manifest: syntheticLicenseManifest(t, tc.sources, tc.replicas)}
			if tc.includeTarget {
				e[target] = tc.targetData
			}
			got, err := buildSINFAssociations(syntheticLicenseFiles(t, e))
			if (err != nil) != tc.wantErr {
				t.Fatalf("associations %v error %v", got, err)
			}
			if !tc.wantErr && got[target] != source {
				t.Fatalf("mapping %v", got)
			}
		})
	}
	t.Run("missing source", func(t *testing.T) {
		_, err := buildSINFAssociations(syntheticLicenseFiles(t, map[string][]byte{manifest: syntheticLicenseManifest(t, []string{sourcePath}, []string{targetPath})}))
		if err == nil {
			t.Fatal("accepted missing source")
		}
	})
}

func TestSINFManifestMultipleSources(t *testing.T) {
	const root = "Payload/A.app/"
	const manifest = root + "SC_Info/Manifest.plist"
	sourceAPath, sourceBPath := "SC_Info/A.sinf", "SC_Info/B.sinf"
	targetAPath, targetBPath := "PlugIns/A.appex/SC_Info/A.sinf", "PlugIns/B.appex/SC_Info/B.sinf"
	sourceA, sourceB := root+sourceAPath, root+sourceBPath
	targetA, targetB := root+targetAPath, root+targetBPath

	t.Run("existing replicas select their exact source", func(t *testing.T) {
		entries := map[string][]byte{
			sourceA: []byte("source-a"), sourceB: []byte("source-b"),
			targetA: []byte("source-a"), targetB: []byte("source-b"),
			manifest: syntheticLicenseManifest(t, []string{sourceBPath, sourceAPath}, []string{targetAPath, targetBPath}),
		}
		got, err := buildSINFAssociations(syntheticLicenseFiles(t, entries))
		if err != nil || got[targetA] != sourceA || got[targetB] != sourceB {
			t.Fatalf("associations %v error %v", got, err)
		}
	})

	t.Run("missing replica with distinct sources is ambiguous", func(t *testing.T) {
		entries := map[string][]byte{
			sourceA: []byte("source-a"), sourceB: []byte("source-b"),
			manifest: syntheticLicenseManifest(t, []string{sourceAPath, sourceBPath}, []string{targetAPath}),
		}
		if _, err := buildSINFAssociations(syntheticLicenseFiles(t, entries)); err == nil || !strings.Contains(err.Error(), "multiple distinct") {
			t.Fatalf("ambiguous replica returned %v", err)
		}
	})

	t.Run("identical sources resolve missing replica deterministically", func(t *testing.T) {
		entries := map[string][]byte{
			sourceA: []byte("same"), sourceB: []byte("same"),
			manifest: syntheticLicenseManifest(t, []string{sourceBPath, sourceAPath}, []string{targetAPath}),
		}
		got, err := buildSINFAssociations(syntheticLicenseFiles(t, entries))
		if err != nil || got[targetA] != sourceA {
			t.Fatalf("associations %v error %v", got, err)
		}
	})

	t.Run("independent sources need no replication mapping", func(t *testing.T) {
		entries := map[string][]byte{
			sourceA: []byte("source-a"), sourceB: []byte("source-b"),
			manifest: syntheticLicenseManifest(t, []string{sourceAPath, sourceBPath}, nil),
		}
		got, err := buildSINFAssociations(syntheticLicenseFiles(t, entries))
		if err != nil || len(got) != 0 {
			t.Fatalf("associations %v error %v", got, err)
		}
	})
}

type syntheticSUPFArch struct {
	cpu, sub uint32
	hash     [20]byte
	records  [][32]byte
}

func syntheticSUPF(variant byte, arches ...syntheticSUPFArch) []byte {
	var body bytes.Buffer
	_ = binary.Write(&body, binary.BigEndian, uint32(len(arches)))
	for _, a := range arches {
		n := 8 + 4 + len(a.records)*32
		if variant == 3 {
			n += 20
		}
		_ = binary.Write(&body, binary.BigEndian, uint32(n))
		_ = binary.Write(&body, binary.BigEndian, a.cpu)
		_ = binary.Write(&body, binary.BigEndian, a.sub)
		if variant == 3 {
			body.Write(a.hash[:])
		}
		_ = binary.Write(&body, binary.BigEndian, uint32(len(a.records)))
		for _, r := range a.records {
			body.Write(r[:])
		}
	}
	out := make([]byte, 8)
	out[0] = variant
	binary.BigEndian.PutUint32(out[4:], uint32(body.Len()))
	return append(out, body.Bytes()...)
}

func TestSelectSUPFVariantsAndSignatureBinding(t *testing.T) {
	const member = "Payload/A.app/A"
	const legacy = "Payload/A.app/SC_Info/A.supf"
	const v5 = "Payload/A.app/SC_Info/A.v5.supf"
	exe := []byte("header and complete signature payload")
	layout := machoLayout{cpuType: 12, cpuSubtype: 2, signatureOffset: 11, signatureSize: uint32(len(exe) - 11)}
	a := syntheticSUPFArch{cpu: 12, sub: 2, hash: sha1.Sum(exe[11:]), records: [][32]byte{{1, 2, 3}}}
	b := syntheticSUPFArch{cpu: 13, sub: 0, hash: [20]byte{3}, records: [][32]byte{{4}}}
	legacyData := syntheticSUPF(3, a, b)
	v5Data := syntheticSUPF(5, b, a)
	for _, tc := range []struct {
		name    string
		files   map[string][]byte
		want    string
		wantErr bool
	}{
		{"v3", map[string][]byte{legacy: legacyData}, legacy, false},
		{"v5", map[string][]byte{v5: v5Data}, v5, false},
		{"both same records different order", map[string][]byte{legacy: legacyData, v5: v5Data}, v5, false},
		{"empty placeholder with v5", map[string][]byte{legacy: nil, v5: v5Data}, v5, false},
		{"empty placeholder alone", map[string][]byte{legacy: nil}, "", true},
		{"empty v5", map[string][]byte{v5: nil}, "", true},
		{"wrong variant", map[string][]byte{legacy: v5Data}, "", true},
		{"v5 wrong suffix variant", map[string][]byte{v5: legacyData}, "", true},
		{"duplicate architecture", map[string][]byte{v5: syntheticSUPF(5, a, a)}, "", true},
		{"mismatched records", map[string][]byte{legacy: legacyData, v5: syntheticSUPF(5, a, syntheticSUPFArch{cpu: 13, sub: 0, records: [][32]byte{{5}}})}, "", true},
		{"mismatched architecture", map[string][]byte{legacy: legacyData, v5: syntheticSUPF(5, a)}, "", true},
		{"malformed legacy cannot be bypassed", map[string][]byte{legacy: []byte{3}, v5: v5Data}, "", true},
		{"missing", map[string][]byte{}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, s, err := selectSUPF(syntheticLicenseFiles(t, tc.files), member)
			if (err != nil) != tc.wantErr {
				t.Fatalf("name=%s err=%v", name, err)
			}
			if tc.wantErr {
				return
			}
			if name != tc.want {
				t.Fatalf("name %q", name)
			}
			for _, v := range s.architectures {
				if v.cpuType != a.cpu || v.cpuSubtype != a.sub {
					continue
				}
				if _, hasLegacy := tc.files[legacy]; hasLegacy && len(tc.files[legacy]) > 0 {
					if !v.HasSignatureSHA1 || v.SignatureSHA1 != a.hash {
						t.Fatal("missing v3 signature binding")
					}
					if err := validateSUPFSignatureBinding(exe, layout, v.SignatureSHA1); err != nil {
						t.Fatal(err)
					}
					wrong := append([]byte(nil), exe...)
					wrong[len(wrong)-1] ^= 1
					if err := validateSUPFSignatureBinding(wrong, layout, v.SignatureSHA1); err == nil {
						t.Fatal("accepted changed signature")
					}
					invalid := layout
					invalid.signatureSize++
					if err := validateSUPFSignatureBinding(exe, invalid, v.SignatureSHA1); err == nil {
						t.Fatal("accepted invalid extent")
					}
				}
			}
		})
	}
}

func TestSINFManifestRejectsOverlappingMappings(t *testing.T) {
	const root = "Payload/A.app/"
	const target = "PlugIns/B.appex/SC_Info/B.sinf"
	const nested = "PlugIns/B.appex/"
	entries := map[string][]byte{root + "SC_Info/A.sinf": []byte("source"), root + nested + "SC_Info/B.sinf": []byte("source"), root + "SC_Info/Manifest.plist": syntheticLicenseManifest(t, []string{"SC_Info/A.sinf"}, []string{target}), root + nested + "SC_Info/Manifest.plist": syntheticLicenseManifest(t, []string{"SC_Info/B.sinf"}, []string{"SC_Info/B.sinf"})}
	_, err := buildSINFAssociations(syntheticLicenseFiles(t, entries))
	if err == nil || !strings.Contains(err.Error(), "multiple manifest mappings") {
		t.Fatalf("overlap error: %v", err)
	}
}

func TestSINFManifestRejectsEscapingRoot(t *testing.T) {
	for _, root := range []string{"..", "../outside"} {
		entries := map[string][]byte{root + "/SC_Info/Manifest.plist": syntheticLicenseManifest(t, []string{"SC_Info/A.sinf"}, nil), root + "/SC_Info/A.sinf": []byte("source")}
		if _, err := buildSINFAssociations(syntheticLicenseFiles(t, entries)); err == nil {
			t.Fatalf("accepted escaping root %q", root)
		}
	}
}
