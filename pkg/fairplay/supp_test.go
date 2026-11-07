package fairplay

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

type syntheticSUPPSigner struct {
	authority, leaf *rsa.PrivateKey
	certificate     []byte
}

func newSyntheticSUPPSigner(t *testing.T) syntheticSUPPSigner {
	t.Helper()
	ca, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Apple FairPlay Certification Authority", Organization: []string{"Apple Inc."}, OrganizationalUnit: []string{"Apple Certification Authority"}}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(4102444800, 0)}
	child := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "SINF.test", Organization: []string{"Apple Inc."}, OrganizationalUnit: []string{"Apple FairPlay"}}, SignatureAlgorithm: x509.SHA1WithRSA, NotBefore: issuer.NotBefore, NotAfter: issuer.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature}
	cert, err := x509.CreateCertificate(rand.Reader, child, issuer, &leaf.PublicKey, ca)
	if err != nil {
		t.Fatal(err)
	}
	return syntheticSUPPSigner{ca, leaf, cert}
}
func (s syntheticSUPPSigner) encode(t *testing.T, variant byte, hash [20]byte, records [][32]byte) []byte {
	t.Helper()
	prefix := []byte{variant, 0, 0, 0}
	if variant == 1 {
		prefix = append(prefix, hash[:]...)
	}
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(records)))
	prefix = append(prefix, count[:]...)
	for _, r := range records {
		prefix = append(prefix, r[:]...)
	}
	var digest []byte
	kind := crypto.SHA256
	if variant == 1 {
		v := sha1.Sum(prefix)
		digest = v[:]
		kind = crypto.SHA1
	} else {
		v := sha256.Sum256(prefix)
		digest = v[:]
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.leaf, kind, digest)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(count[:], uint32(len(s.certificate)))
	result := append(append([]byte(nil), prefix...), count[:]...)
	result = append(result, s.certificate...)
	return append(result, signature...)
}
func TestSUPPSignedEnvelopesAndPageMapping(t *testing.T) {
	signer := newSyntheticSUPPSigner(t)
	signature := []byte("synthetic complete signature")
	hash := sha1.Sum(signature)
	records := [][32]byte{{1}, {2}, {3}, {4}}
	for _, v := range []byte{1, 4} {
		t.Run(string(rune('0'+v)), func(t *testing.T) {
			blob := signer.encode(t, v, hash, records)
			s, err := parseSUPPWithCA(blob, &signer.authority.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if s.variant != v || len(s.records) != 4 || s.HasSignatureSHA1 != (v == 1) {
				t.Fatalf("wrong parsed geometry: %+v", s)
			}
			if v == 1 && s.SignatureSHA1 != hash {
				t.Fatal("hash not preserved")
			}
			tail, err := s.recordsForLayout(machoLayout{cryptOffset: 8192, cryptSize: 8192})
			if err != nil || len(tail) != 2 || tail[0] != records[2] || tail[1] != records[3] {
				t.Fatalf("tail=%v err=%v", tail, err)
			}
			if v == 1 {
				layout := machoLayout{signatureSize: uint32(len(signature))}
				if err := validateSUPFSignatureBinding(signature, layout, s.SignatureSHA1); err != nil {
					t.Fatal(err)
				}
				changed := append([]byte(nil), signature...)
				changed[0] ^= 1
				if err := validateSUPFSignatureBinding(changed, layout, s.SignatureSHA1); err == nil {
					t.Fatal("accepted wrong signature hash")
				}
			}
		})
	}
	for _, layout := range []machoLayout{{cryptOffset: 1, cryptSize: 4096}, {cryptOffset: 4096, cryptSize: 1}, {cryptOffset: 0, cryptSize: 0}, {cryptOffset: 4096, cryptSize: 4096}} {
		if _, err := (supp{records: records}).recordsForLayout(layout); err == nil {
			t.Fatalf("accepted invalid range %+v", layout)
		}
	}
}
func TestSUPPRejectsMalformedAndUnauthenticated(t *testing.T) {
	signer := newSyntheticSUPPSigner(t)
	valid := signer.encode(t, 1, [20]byte{}, [][32]byte{{1}})
	wrongAuthority, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		edit func([]byte) []byte
		ca   *rsa.PublicKey
	}{
		{"truncated header", func(b []byte) []byte { return b[:3] }, &signer.authority.PublicKey},
		{"unsupported version", func(b []byte) []byte { b[0] = 2; return b }, &signer.authority.PublicKey},
		{"truncated signature hash", func(b []byte) []byte { return b[:22] }, &signer.authority.PublicKey},
		{"unbounded page count", func(b []byte) []byte { binary.BigEndian.PutUint32(b[24:28], ^uint32(0)); return b }, &signer.authority.PublicKey},
		{"zero page count", func(b []byte) []byte { clear(b[24:28]); return b }, &signer.authority.PublicKey},
		{"prefix record modified", func(b []byte) []byte { b[28] ^= 1; return b }, &signer.authority.PublicKey},
		{"wrong authority", func(b []byte) []byte { return b }, &wrongAuthority.PublicKey},
		{"wrong signature", func(b []byte) []byte { b[len(b)-1] ^= 1; return b }, &signer.authority.PublicKey},
		{"certificate truncated", func(b []byte) []byte { binary.BigEndian.PutUint32(b[60:64], 100000); return b }, &signer.authority.PublicKey},
		{"trailing byte", func(b []byte) []byte { return append(b, 1) }, &signer.authority.PublicKey},
		{"truncated signature", func(b []byte) []byte { return b[:len(b)-1] }, &signer.authority.PublicKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.edit(bytes.Clone(valid))
			if _, err := parseSUPPWithCA(data, tc.ca); err == nil {
				t.Fatal("accepted invalid SUPP")
			}
		})
	}
}

func TestSelectImageKeyTableSUPPResolution(t *testing.T) {
	const member = "Payload/A.app/A"
	const p1 = "Payload/A.app/SC_Info/A.supp"
	const p4 = "Payload/A.app/SC_Info/A.v4.supp"
	const f5 = "Payload/A.app/SC_Info/A.v5.supf"
	signer := newSyntheticSUPPSigner(t)
	signature := []byte("complete synthetic code signature")
	hash := sha1.Sum(signature)
	records := [][32]byte{{1}, {2}, {3}, {4}}
	v1 := signer.encode(t, 1, hash, records)
	v4 := signer.encode(t, 4, hash, records)
	alternate := append([][32]byte(nil), records...)
	alternate[3][0] ^= 0x80
	different := signer.encode(t, 4, hash, alternate)
	fewer := signer.encode(t, 4, hash, records[:3])
	layout := machoLayout{cpuType: 12, cpuSubtype: 2, cryptOffset: 8192, cryptSize: 8192, cryptID: 1, signatureSize: uint32(len(signature))}
	thin := []machoSlice{{layout: layout}}
	fat := []machoSlice{{offset: 4096, layout: layout}}
	fdata := syntheticSUPF(5, syntheticSUPFArch{cpu: 12, sub: 2, records: records[2:]})
	tests := []struct {
		name           string
		entries        map[string][]byte
		slices         []machoSlice
		selected       string
		bound, wantErr bool
	}{
		{"thin v1", map[string][]byte{p1: v1}, thin, p1, true, false},
		{"thin v4", map[string][]byte{p4: v4}, thin, p4, false, false},
		{"equivalent variants use v4 with v1 binding", map[string][]byte{p1: v1, p4: v4}, thin, p4, true, false},
		{"different records rejected", map[string][]byte{p1: v1, p4: different}, thin, "", false, true},
		{"different record counts rejected", map[string][]byte{p1: v1, p4: fewer}, thin, "", false, true},
		{"wrong v1 suffix", map[string][]byte{p1: v4}, thin, "", false, true},
		{"wrong v4 suffix", map[string][]byte{p4: v1}, thin, "", false, true},
		{"missing key table", map[string][]byte{}, thin, "", false, true},
		{"malformed pclass", map[string][]byte{p1: {1}}, thin, "", false, true},
		{"malformed p4 does not fall back to p1", map[string][]byte{p1: v1, p4: {4}}, thin, "", false, true},
		{"malformed p1 does not fall back to p4", map[string][]byte{p1: {1}, p4: v4}, thin, "", false, true},
		{"universal record coverage required", map[string][]byte{p1: v1}, fat, "", false, true},
		{"duplicate universal architecture rejected", map[string][]byte{p1: v1}, []machoSlice{{size: 20000, layout: layout}, {size: 20000, layout: layout}}, "", false, true},
		{"malformed fclass does not fall back", map[string][]byte{f5: {5}, p1: v1}, thin, "", false, true},
		{"fclass takes precedence over malformed pclass", map[string][]byte{f5: fdata, p1: {1}}, thin, f5, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, table, err := selectImageKeyTableWithCA(syntheticLicenseFiles(t, tc.entries), member, tc.slices, &signer.authority.PublicKey)
			if (err != nil) != tc.wantErr {
				t.Fatalf("name %q error %v", name, err)
			}
			if tc.wantErr {
				return
			}
			if name != tc.selected || len(table.architectures) != 1 {
				t.Fatalf("name %q table %+v", name, table)
			}
			a := table.architectures[0]
			if a.cpuType != layout.cpuType || a.cpuSubtype != layout.cpuSubtype || len(a.records) != 2 || a.records[0] != records[2] || a.records[1] != records[3] {
				t.Fatalf("wrong architecture or records: %+v", a)
			}
			if a.HasSignatureSHA1 != tc.bound {
				t.Fatalf("binding=%v want %v", a.HasSignatureSHA1, tc.bound)
			}
			if tc.bound {
				if a.SignatureSHA1 != hash {
					t.Fatal("missing v1 hash")
				}
				if err := table.ValidateSignatureBinding(signature, layout); err != nil {
					t.Fatal(err)
				}
				modified := bytes.Clone(signature)
				modified[0] ^= 1
				if err := table.ValidateSignatureBinding(modified, layout); err == nil {
					t.Fatal("accepted signature mismatch")
				}
			}
		})
	}
}

func TestSelectImageKeyTableUniversalSUPP(t *testing.T) {
	const member = "Payload/A.app/A"
	const p1 = "Payload/A.app/SC_Info/A.supp"
	const p4 = "Payload/A.app/SC_Info/A.v4.supp"
	signer := newSyntheticSUPPSigner(t)
	records := make([][32]byte, 11)
	for index := range records {
		records[index][0] = byte(index)
	}
	v4 := signer.encode(t, 4, [20]byte{}, records)
	slices := []machoSlice{
		{offset: 0x4000, size: 0x3000, layout: machoLayout{cpuType: cpuTypeARM, cpuSubtype: 9, cryptOffset: 0x1000, cryptSize: 0x1000, cryptID: 1, signatureOffset: 0x2000, signatureSize: 4}},
		{offset: 0x8000, size: 0x4000, layout: machoLayout{cpuType: cpuTypeARM64, cryptOffset: 0x1000, cryptSize: 0x2000, cryptID: 1, signatureOffset: 0x3000, signatureSize: 4}},
	}
	name, table, err := selectImageKeyTableWithCA(syntheticLicenseFiles(t, map[string][]byte{p4: v4}), member, slices, &signer.authority.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if name != p4 || len(table.architectures) != 2 {
		t.Fatalf("name %q table %+v", name, table)
	}
	arm, err := table.recordsFor(cpuTypeARM, 9)
	if err != nil || len(arm) != 1 || arm[0] != records[5] {
		t.Fatalf("ARM records %v error %v", arm, err)
	}
	arm64, err := table.recordsFor(cpuTypeARM64, 0)
	if err != nil || len(arm64) != 2 || arm64[0] != records[9] || arm64[1] != records[10] {
		t.Fatalf("ARM64 records %v error %v", arm64, err)
	}

	executable := make([]byte, 0xc000)
	copy(executable[0x6000:], []byte("one!"))
	copy(executable[0xb000:], []byte("two!"))
	joined := sha1.Sum([]byte("one!two!"))
	legacy := signer.encode(t, 1, joined, records)
	_, legacyTable, err := selectImageKeyTableWithCA(syntheticLicenseFiles(t, map[string][]byte{p1: legacy}), member, slices, &signer.authority.PublicKey)
	if err != nil || !legacyTable.HasUniversalSignatureSHA1 {
		t.Fatalf("legacy universal SUPP returned %+v, %v", legacyTable, err)
	}
	if err := legacyTable.ValidateUniversalSignatureBinding(executable, slices); err != nil {
		t.Fatal(err)
	}
	executable[0xb000] ^= 1
	if err := legacyTable.ValidateUniversalSignatureBinding(executable, slices); err == nil {
		t.Fatal("accepted changed universal code signature")
	}
	for _, count := range []int{10, 12} {
		wrong := signer.encode(t, 4, [20]byte{}, records[:min(count, len(records))])
		if count > len(records) {
			wrong = signer.encode(t, 4, [20]byte{}, append(records, [32]byte{12}))
		}
		if _, _, err := selectImageKeyTableWithCA(syntheticLicenseFiles(t, map[string][]byte{p4: wrong}), member, slices, &signer.authority.PublicKey); err == nil {
			t.Fatalf("accepted universal SUPP with %d records", count)
		}
	}
}
