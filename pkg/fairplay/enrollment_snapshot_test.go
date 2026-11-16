package fairplay

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func syntheticEnrollmentSnapshot() EnrollmentSnapshot {
	return EnrollmentSnapshot{Hardware: [6]byte{0, 1, 2, 3, 4, 5}, SIDB: []byte{0, 7, 0, 11, 1, 2, 3}, ProductVersion: "26.0", BuildVersion: "synthetic"}
}

func TestEnrollmentSnapshotEnvelope(t *testing.T) {
	snapshot := syntheticEnrollmentSnapshot()
	data, err := snapshot.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseEnrollmentSnapshot(data)
	if err != nil || got.Hardware != snapshot.Hardware || got.ProductVersion != snapshot.ProductVersion || got.BuildVersion != snapshot.BuildVersion || !bytes.Equal(got.SIDB, snapshot.SIDB) {
		t.Fatal("snapshot round trip failed", err)
	}
	clear(data)
	if !bytes.Equal(got.SIDB, snapshot.SIDB) {
		t.Fatal("parser retained caller memory")
	}
	got.Clear()
	if got.Hardware != [6]byte{} || got.SIDB != nil {
		t.Fatal("private snapshot was not cleared")
	}
	data, _ = snapshot.MarshalBinary()
	mutate := func(at int, value byte) []byte { b := bytes.Clone(data); b[at] = value; return b }
	for name, bad := range map[string][]byte{
		"empty": nil, "short": data[:29], "magic": mutate(0, 'X'), "version": mutate(11, 2),
		"size": mutate(15, 0), "product-length": mutate(22, 1), "build-length": mutate(24, 1),
		"sidb-length": mutate(26, 0xff), "truncated": data[:len(data)-1], "trailing": append(bytes.Clone(data), 0),
		"sidb-version": mutate(len(data)-len(snapshot.SIDB)+3, 12), "metadata": mutate(30, 0),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEnrollmentSnapshot(bad); err == nil {
				t.Fatal("accepted malformed snapshot")
			}
		})
	}
	for _, metadata := range []string{"", strings.Repeat("x", 129), "bad\n", "\xff"} {
		bad := snapshot
		bad.ProductVersion = metadata
		if _, err := bad.MarshalBinary(); err == nil {
			t.Fatal("accepted invalid metadata")
		}
	}
	bad := snapshot
	bad.SIDB = make([]byte, maximumSnapshotSIDB+1)
	if _, err := bad.MarshalBinary(); err == nil {
		t.Fatal("accepted oversized SIDB")
	}
}

func TestReadEnrollmentSnapshotPermissionsAndBounds(t *testing.T) {
	data, _ := syntheticEnrollmentSnapshot().MarshalBinary()
	name := filepath.Join(t.TempDir(), "snapshot")
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadEnrollmentSnapshot(name)
	if err != nil {
		t.Fatal(err)
	}
	got.Clear()
	link := name + ".link"
	if err := os.Symlink(name, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEnrollmentSnapshot(link); err == nil {
		t.Fatal("accepted symlink")
	}
	if _, err := ReadEnrollmentSnapshot(filepath.Dir(name)); err == nil {
		t.Fatal("accepted directory")
	}
	if err := os.Chmod(name, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEnrollmentSnapshot(name); err == nil {
		t.Fatal("accepted public snapshot")
	}
	if err := os.Chmod(name, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(name, maximumSnapshotBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEnrollmentSnapshot(name); err == nil {
		t.Fatal("accepted oversized snapshot")
	}
}

func TestCollectEnrollmentSnapshotStateSelection(t *testing.T) {
	root := t.TempDir()
	opts := EnrollmentExportOptions{SystemStatePath: filepath.Join(root, "system"), SharedStatePath: filepath.Join(root, "shared"), MACAddressPath: filepath.Join(root, "hardware"), ProductVersion: "26.0", BuildVersion: "synthetic"}
	for _, dir := range []string{opts.SystemStatePath, opts.SharedStatePath} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(opts.MACAddressPath, []byte{0, 1, 2, 3, 4, 5})
	if _, err := CollectEnrollmentSnapshot(opts); err == nil {
		t.Fatal("accepted missing state")
	}
	system, shared := filepath.Join(opts.SystemStatePath, "SC Info.sidb"), filepath.Join(opts.SharedStatePath, "SC Info.sidb")
	data := syntheticEnrollmentSnapshot().SIDB
	write(system, data)
	for _, duplicate := range []bool{false, true} {
		if duplicate {
			write(shared, data)
		}
		snapshot, err := CollectEnrollmentSnapshot(opts)
		if err != nil || !bytes.Equal(snapshot.SIDB, data) {
			t.Fatal("valid state selection failed", err)
		}
		snapshot.Clear()
	}
	other := bytes.Clone(data)
	other[len(other)-1] ^= 1
	write(shared, other)
	if _, err := CollectEnrollmentSnapshot(opts); err == nil {
		t.Fatal("accepted distinct containers")
	}
	binary.BigEndian.PutUint32(other, 0x7000c)
	write(shared, other)
	if _, err := CollectEnrollmentSnapshot(opts); err == nil {
		t.Fatal("ignored unknown container")
	}
	write(shared, data)
	write(opts.MACAddressPath, []byte{1, 2, 3})
	if _, err := CollectEnrollmentSnapshot(opts); err == nil {
		t.Fatal("accepted short hardware")
	}
	write(opts.MACAddressPath, []byte{0, 1, 2, 3, 4, 5})
	if err := os.Remove(shared); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(system, shared); err != nil {
		t.Fatal(err)
	}
	if _, err := CollectEnrollmentSnapshot(opts); err == nil {
		t.Fatal("accepted symlink state")
	}
}

func FuzzEnrollmentSnapshotEnvelope(f *testing.F) {
	data, _ := syntheticEnrollmentSnapshot().MarshalBinary()
	f.Add(data)
	f.Fuzz(func(t *testing.T, input []byte) {
		s, err := ParseEnrollmentSnapshot(input)
		if err != nil {
			return
		}
		defer s.Clear()
		encoded, err := s.MarshalBinary()
		if err != nil || !bytes.Equal(input, encoded) {
			t.Fatal("accepted noncanonical snapshot", err)
		}
	})
}
