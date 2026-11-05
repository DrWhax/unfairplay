package fairplay

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestCanonicalSIDBClassifiesVersionWithoutInferringGeometry(t *testing.T) {
	for _, test := range []struct {
		bytes, source int
	}{{630, 0}, {642, 0}, {993, 0}, {1003, 0}, {2048, 0}, {8192, 0}} {
		t.Run(fmt.Sprintf("%d", test.bytes), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "SC Info.sidb")
			data := make([]byte, test.bytes)
			binary.BigEndian.PutUint32(data[:4], 0x0007000b)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			sidb, err := canonicalSIDB(CanonicalEnrollmentFile{
				CapturePath: "state/fpsd-sc-info/SC Info.sidb", Bytes: int64(len(data)), localPath: path,
			})
			if err != nil {
				t.Fatal(err)
			}
			if sidb.Version != 0x0007000b || sidb.Format != "macos-sidb-v7000b" || sidb.ExpectedSourceBytes != test.source || sidb.CodecBytes != 0 || sidb.RegistryBytes != 0 || sidb.FooterBytes != 0 {
				t.Fatalf("unexpected SIDB classification: %#v", sidb)
			}
		})
	}
}

func TestCanonicalInputFingerprintExcludesLocalPaths(t *testing.T) {
	base := CanonicalEnrollmentInput{
		Schema: CanonicalEnrollmentInputSchema, Contract: "macos-current-sinf-v1",
		SelectorID: "synthetic:00000002",
		Executable: CanonicalEnrollmentFile{Role: "installed-executable", CapturePath: "app/executable", SHA256: "01", localPath: "/private/one"},
	}
	left, err := canonicalInputFingerprint(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Executable.localPath = "/different/private/path"
	right, err := canonicalInputFingerprint(base)
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatal("canonical fingerprint depends on a private local path")
	}
	base.Executable.SHA256 = "02"
	changed, err := canonicalInputFingerprint(base)
	if err != nil {
		t.Fatal(err)
	}
	if changed == left {
		t.Fatal("canonical fingerprint ignored exported file identity")
	}
}

func TestCanonicalRuntimeMappingsUseNormalizedRoles(t *testing.T) {
	input := CanonicalEnrollmentInput{
		ExecutableName:    "App",
		InstalledSINFFile: CanonicalEnrollmentFile{VirtualPath: "App.sinf", localPath: "/capture/App.sinf"},
		SUPFs: []CanonicalSUPF{
			{File: CanonicalEnrollmentFile{VirtualPath: "App.supp", localPath: "/capture/App.supp"}},
			{File: CanonicalEnrollmentFile{VirtualPath: "App.v4.supp", localPath: "/capture/App.v4.supp"}},
			{File: CanonicalEnrollmentFile{VirtualPath: "Other.supp", localPath: "/capture/Other.supp"}},
			{File: CanonicalEnrollmentFile{VirtualPath: "App.supf", localPath: "/capture/App.supf"}},
			{File: CanonicalEnrollmentFile{VirtualPath: "App.v5.supf", localPath: "/capture/App.v5.supf"}},
			{File: CanonicalEnrollmentFile{VirtualPath: "App.v6.supf", localPath: "/capture/App.v6.supf"}},
		},
		AuxiliaryLicenses: []CanonicalEnrollmentFile{{VirtualPath: "unrelated.sinf", localPath: "/capture/unrelated.sinf"}},
		SIDBs: []CanonicalSIDB{{File: CanonicalEnrollmentFile{
			Role: "fpsd-state", VirtualPath: "/var/db/fpsd/SC Info/SC Info.sidb", localPath: "/capture/SC Info.sidb",
		}}},
		StateFiles: []CanonicalEnrollmentFile{
			{Role: "adi-state", VirtualPath: "/var/db/fpsd/adi/adi.pb", localPath: "/capture/adi.pb"},
			{Role: "fpsd-state", VirtualPath: "/var/db/fpsd/SC Info/SC Info.sids", localPath: "/capture/SC Info.sids"},
		},
	}
	mappings, states := input.RuntimeFileMappings()
	wantMinimal := []string{
		"/var/db/fpsd/SC Info/SC Info.sidb=/capture/SC Info.sidb",
		"/var/db/fpsd/SC Info/SC Info.sids=/capture/SC Info.sids",
		"App.sinf=/capture/App.sinf",
		"App.supf=/capture/App.supf",
		"App.supp=/capture/App.supp",
		"App.v4.supp=/capture/App.v4.supp",
		"App.v5.supf=/capture/App.v5.supf",
	}
	if states != 2 || !slices.Equal(mappings, wantMinimal) {
		t.Fatalf("runtime mappings = %#v, state files = %d", mappings, states)
	}
}

func TestCanonicalSUPPMetadataRequiresAuthenticatedEnvelope(t *testing.T) {
	signer := newSyntheticSUPPSigner(t)
	for _, tc := range []struct {
		name    string
		variant byte
	}{{"App.supp", 1}, {"App.v4.supp", 4}} {
		t.Run(tc.name, func(t *testing.T) {
			data := signer.encode(t, tc.variant, [20]byte{}, [][32]byte{{1}, {2}, {3}})
			path := filepath.Join(t.TempDir(), tc.name)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			file := CanonicalEnrollmentFile{CapturePath: tc.name, VirtualPath: tc.name, localPath: path}
			metadata, err := canonicalSUPFWithSUPPAuthority(file, &signer.authority.PublicKey)
			if err != nil || metadata.Variant != tc.variant || metadata.FileOriginPages != 3 || len(metadata.Architectures) != 0 {
				t.Fatalf("SUPP metadata = %+v, %v", metadata, err)
			}
			if _, err := canonicalSUPF(file); err == nil {
				t.Fatal("synthetic authority accepted by production parser")
			}
			tampered := bytes.Clone(data)
			tampered[len(tampered)-1] ^= 1
			if err := os.WriteFile(path, tampered, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := canonicalSUPFWithSUPPAuthority(file, &signer.authority.PublicKey); err == nil {
				t.Fatal("accepted tampered SUPP")
			}
		})
	}
}
