package fairplay

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"unicode/utf8"
)

const (
	enrollmentSnapshotMagic  = "UFENRS1\x00"
	enrollmentSnapshotHeader = 30
	// Bounds are tool restrictions, not claims about all native formats.
	maximumSnapshotSIDB     = (1 << 20) + 4096
	maximumSnapshotMetadata = 128
	maximumSnapshotBytes    = enrollmentSnapshotHeader + 2*maximumSnapshotMetadata + maximumSnapshotSIDB
)

// EnrollmentSnapshot contains private source state, not a validated model.
// SIDB authentication and the exact SINF route must still pass during recovery.
type EnrollmentSnapshot struct {
	Hardware                     [6]byte
	SIDB                         []byte
	ProductVersion, BuildVersion string
}

func (s *EnrollmentSnapshot) Clear() {
	clear(s.Hardware[:])
	clear(s.SIDB)
	s.SIDB = nil
}

func validSnapshotMetadata(s string) bool {
	if len(s) == 0 || len(s) > maximumSnapshotMetadata || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (s EnrollmentSnapshot) validate() error {
	if !validSnapshotMetadata(s.ProductVersion) || !validSnapshotMetadata(s.BuildVersion) {
		return fmt.Errorf("invalid enrollment snapshot OS metadata")
	}
	if len(s.SIDB) < 4 || len(s.SIDB) > maximumSnapshotSIDB || binary.BigEndian.Uint32(s.SIDB[:4]) != 0x0007000b {
		return fmt.Errorf("unsupported enrollment snapshot SIDB version or size")
	}
	return nil
}

// MarshalBinary emits an exact-length, versioned envelope. It adds no signature;
// recovery authenticates the contained native SIDB independently.
func (s EnrollmentSnapshot) MarshalBinary() ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	out := make([]byte, enrollmentSnapshotHeader, enrollmentSnapshotHeader+len(s.ProductVersion)+len(s.BuildVersion)+len(s.SIDB))
	copy(out, enrollmentSnapshotMagic)
	binary.BigEndian.PutUint32(out[8:12], 1)
	binary.BigEndian.PutUint32(out[12:16], uint32(cap(out)))
	copy(out[16:22], s.Hardware[:])
	binary.BigEndian.PutUint16(out[22:24], uint16(len(s.ProductVersion)))
	binary.BigEndian.PutUint16(out[24:26], uint16(len(s.BuildVersion)))
	binary.BigEndian.PutUint32(out[26:30], uint32(len(s.SIDB)))
	out = append(out, s.ProductVersion...)
	out = append(out, s.BuildVersion...)
	out = append(out, s.SIDB...)
	return out, nil
}

func ParseEnrollmentSnapshot(data []byte) (EnrollmentSnapshot, error) {
	var s EnrollmentSnapshot
	if len(data) < enrollmentSnapshotHeader || len(data) > maximumSnapshotBytes ||
		string(data[:8]) != enrollmentSnapshotMagic || binary.BigEndian.Uint32(data[8:12]) != 1 ||
		uint64(binary.BigEndian.Uint32(data[12:16])) != uint64(len(data)) {
		return s, fmt.Errorf("invalid enrollment snapshot envelope")
	}
	p, b := int(binary.BigEndian.Uint16(data[22:24])), int(binary.BigEndian.Uint16(data[24:26]))
	n := uint64(binary.BigEndian.Uint32(data[26:30]))
	if p > maximumSnapshotMetadata || b > maximumSnapshotMetadata || uint64(enrollmentSnapshotHeader+p+b)+n != uint64(len(data)) {
		return s, fmt.Errorf("invalid enrollment snapshot field lengths")
	}
	copy(s.Hardware[:], data[16:22])
	s.ProductVersion = string(data[30 : 30+p])
	s.BuildVersion = string(data[30+p : 30+p+b])
	s.SIDB = data[30+p+b:]
	if err := s.validate(); err != nil {
		return EnrollmentSnapshot{}, err
	}
	s.SIDB = bytes.Clone(s.SIDB)
	return s, nil
}

// Read a bounded regular file, validating the opened object as well as its
// original directory entry. Secret inputs must have private permissions.
func readSnapshotFile(name string, limit int64, private bool) ([]byte, error) {
	before, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("snapshot input must be a regular file")
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, info) || !info.Mode().IsRegular() || info.Size() > limit || private && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("snapshot input changed, exceeds its size limit, or has unsafe permissions")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		clear(data)
		return nil, fmt.Errorf("could not read bounded snapshot input")
	}
	return data, nil
}

func ReadEnrollmentSnapshot(name string) (EnrollmentSnapshot, error) {
	if err := checkPlatform(); err != nil {
		return EnrollmentSnapshot{}, err
	}
	data, err := readSnapshotFile(name, maximumSnapshotBytes, true)
	if err != nil {
		return EnrollmentSnapshot{}, err
	}
	defer clear(data)
	return ParseEnrollmentSnapshot(data)
}

type EnrollmentExportOptions struct {
	SystemStatePath, SharedStatePath, MACAddressPath, HardwareInterface string
	ProductVersion, BuildVersion                                        string
}

// CollectEnrollmentSnapshot captures only inputs consumed by mapped recovery.
// Both configured state locations are inspected; distinct containers reject.
// The caller must authenticate the SIDB before publishing this snapshot.
func CollectEnrollmentSnapshot(options EnrollmentExportOptions) (snapshot EnrollmentSnapshot, err error) {
	defer func() {
		if err != nil {
			snapshot.Clear()
		}
	}()
	if err = checkPlatform(); err != nil {
		return snapshot, err
	}
	if runtime.GOOS != "darwin" && (options.ProductVersion == "" || options.BuildVersion == "" || options.MACAddressPath == "") {
		return snapshot, fmt.Errorf("native enrollment export requires macOS")
	}
	if options.SystemStatePath == "" {
		options.SystemStatePath = "/private/var/db/fpsd/SC Info"
	}
	if options.SharedStatePath == "" {
		options.SharedStatePath = "/Users/Shared/SC Info"
	}
	for _, dir := range []string{options.SystemStatePath, options.SharedStatePath} {
		data, readErr := readSnapshotFile(filepath.Join(dir, "SC Info.sidb"), maximumSnapshotSIDB, false)
		if os.IsNotExist(readErr) {
			continue
		}
		if readErr != nil {
			return snapshot, readErr
		}
		if len(data) < 4 || binary.BigEndian.Uint32(data[:4]) != 0x0007000b {
			clear(data)
			return snapshot, fmt.Errorf("unsupported exported SIDB version")
		}
		if snapshot.SIDB != nil {
			equal := bytes.Equal(snapshot.SIDB, data)
			clear(data)
			if !equal {
				return snapshot, fmt.Errorf("enrollment export requires one distinct SIDB container")
			}
		} else {
			snapshot.SIDB = data
		}
	}
	if snapshot.SIDB == nil {
		return snapshot, fmt.Errorf("no enrollment SIDB found")
	}
	var hardware []byte
	if options.MACAddressPath != "" {
		hardware, err = readSnapshotFile(options.MACAddressPath, 6, true)
	} else {
		if options.HardwareInterface == "" {
			options.HardwareInterface = "en0"
		}
		hardware, err = ioregHardwareMAC(options.HardwareInterface)
	}
	defer clear(hardware)
	if err != nil {
		return snapshot, err
	}
	if len(hardware) != 6 {
		return snapshot, fmt.Errorf("enrollment export requires a six-byte hardware identity")
	}
	copy(snapshot.Hardware[:], hardware)
	snapshot.ProductVersion, snapshot.BuildVersion = options.ProductVersion, options.BuildVersion
	if snapshot.ProductVersion == "" {
		snapshot.ProductVersion, err = querySystemVersion("-productVersion")
		if err != nil {
			return snapshot, err
		}
	}
	if snapshot.BuildVersion == "" {
		snapshot.BuildVersion, err = querySystemVersion("-buildVersion")
		if err != nil {
			return snapshot, err
		}
	}
	err = snapshot.validate()
	return snapshot, err
}
