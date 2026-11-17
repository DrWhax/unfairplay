package fairplay

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func dumpTestPack(version uint32) []byte {
	var magic string
	var size int
	switch version {
	case 1:
		magic, size = enrollmentModelV1Magic, currentSINFModelV1Bytes
	case 2:
		magic, size = enrollmentModelV2Magic, currentSINFModelV2Bytes
	default:
		magic, size = enrollmentModelV3Magic, currentSINFModelV3Bytes
	}
	pack := make([]byte, 0, size)
	word := func(v uint32) { pack = binary.LittleEndian.AppendUint32(pack, v) }
	tables := func() {
		for range 16 {
			for v := range 256 {
				pack = append(pack, byte(255-v))
			}
		}
	}
	pack = append(pack, magic...)
	word(version)
	word(uint32(size))
	pack = append(pack, bytes.Repeat([]byte{0xaa}, 32)...)
	if version >= 2 {
		word(0x11223344)
		word(7)
	}
	if version == 3 {
		word(9)
		word(currentSINFV3SourceBytes)
		pack = append(pack, 0x5a, 0, 0, 0)
	}
	pack = append(pack, bytes.Repeat([]byte{0xbb}, 16)...)
	if version < 3 {
		pack = append(pack, bytes.Repeat([]byte{0xcc}, 16)...)
		tables()
	} else {
		tables()
		pack = append(pack, bytes.Repeat([]byte{0xdd}, currentSINFV3SourceBytes)...)
		tables()
	}
	return pack
}

func TestDumpEnrollmentModelAllVersions(t *testing.T) {
	for _, version := range []uint32{1, 2, 3} {
		pack := dumpTestPack(version)
		path := filepath.Join(t.TempDir(), "model.bin")
		if err := os.WriteFile(path, pack, 0o600); err != nil {
			t.Fatal(err)
		}
		dump, err := DumpEnrollmentModel(path, true)
		if err != nil {
			t.Fatalf("v%d: %v", version, err)
		}
		if dump.Version != version || dump.Key != strings.Repeat("bb", 16) || dump.UnaccountedTrailing != 0 {
			t.Fatalf("v%d: unexpected dump %+v", version, dump)
		}
		var rebuilt []byte
		for _, f := range dump.Layout {
			if f.Offset != len(rebuilt) {
				t.Fatalf("v%d: layout gap at %s", version, f.Name)
			}
			b, _ := hex.DecodeString(f.Hex)
			rebuilt = append(rebuilt, b...)
		}
		if !bytes.Equal(rebuilt, pack) || dump.Raw != hex.EncodeToString(pack) {
			t.Fatalf("v%d: layout does not reproduce file", version)
		}
		if version >= 2 && (dump.Selector == nil || dump.SelectorID != "11223344:00000007") {
			t.Fatalf("v%d: selector %+v", version, dump.Selector)
		}
		if version == 3 && (*dump.FinalXOR != 0x5a || len(dump.PostDecodeTables) != 16 || dump.OutputMask == "") {
			t.Fatalf("v3: fields %+v", dump)
		}
		var out bytes.Buffer
		if err := WriteModelDumpText(&out, dump); err != nil || !strings.Contains(out.String(), "Key:") {
			t.Fatalf("v%d: text output %v", version, err)
		}
	}
}

func TestDumpEnrollmentModelRejectsGroupReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "model.bin")
	if err := os.WriteFile(path, dumpTestPack(2), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := DumpEnrollmentModel(path, false); err == nil {
		t.Fatal("expected permission error")
	}
}
