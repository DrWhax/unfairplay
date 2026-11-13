package fairplay

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"howett.net/plist"
)

// A synthetic arm64 executable with a bounded zero-filled header gap.
func macOSFixtureMachO(legacy bool) []byte {
	b := make([]byte, 1024)
	put := func(at int, value uint32) { binary.LittleEndian.PutUint32(b[at:at+4], value) }
	put(0, mhMagic64)
	put(4, cpuTypeARM64)
	put(12, 2)
	put(16, 3)
	versionSize := 24
	if legacy {
		versionSize = 16
	}
	put(20, uint32(152+versionSize+24))
	put(32, lcSegment64)
	put(36, 152)
	binary.LittleEndian.PutUint64(b[64:72], 1024)
	binary.LittleEndian.PutUint64(b[80:88], 1024)
	put(96, 1)
	copy(b[104:120], "__text")
	copy(b[120:136], "__TEXT")
	binary.LittleEndian.PutUint64(b[144:152], 16)
	put(152, 512)
	put(168, sectionAttrPureInstructions)
	if legacy {
		put(184, 0x25)
		put(188, 16)
		put(192, 12<<16)
	} else {
		put(184, lcBuildVersion)
		put(188, 24)
		put(192, 2)
		put(196, 14<<16)
		put(200, 17<<16)
	}
	at := 184 + versionSize
	put(at, lcEncryptionInfo64)
	put(at+4, 24)
	for i := 512; i < 528; i++ {
		b[i] = 0xcc
	}
	return b
}

func TestConvertDecryptedMachO(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		input := macOSFixtureMachO(legacy)
		original := bytes.Clone(input)
		out, err := convertDecryptedMachO(input)
		if err != nil {
			t.Fatal(err)
		}
		if binary.LittleEndian.Uint32(out[184:188]) != lcBuildVersion || binary.LittleEndian.Uint32(out[192:196]) != 6 {
			t.Fatal("not Catalyst")
		}
		if !bytes.Equal(input, original) || !bytes.Equal(out[512:], input[512:]) {
			t.Fatal("changed input or code")
		}
		if _, err := parseMachOSlices(out, uint64(len(out))); err != nil {
			t.Fatal(err)
		}
	}
}

func TestConvertDecryptedMachORejections(t *testing.T) {
	cases := map[string]func([]byte){
		"encrypted":        func(b []byte) { binary.LittleEndian.PutUint32(b[224:228], 1) },
		"arm64e":           func(b []byte) { binary.LittleEndian.PutUint32(b[8:12], 2) },
		"unknown platform": func(b []byte) { binary.LittleEndian.PutUint32(b[192:196], 99) },
		"duplicate version": func(b []byte) {
			binary.LittleEndian.PutUint32(b[208:212], lcBuildVersion)
			binary.LittleEndian.PutUint32(b[216:220], 2)
		},
		"bad build tools": func(b []byte) { binary.LittleEndian.PutUint32(b[204:208], 3) },
		"bad commands":    func(b []byte) { binary.LittleEndian.PutUint32(b[188:192], 0xffffffff) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := macOSFixtureMachO(false)
			mutate(b)
			if _, err := convertDecryptedMachO(b); err == nil {
				t.Fatal("accepted invalid image")
			}
		})
	}
	for _, test := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"nonzero gap", func(b []byte) { b[224] = 1 }},
		{"no padding", func(b []byte) { binary.LittleEndian.PutUint32(b[152:156], 224) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := macOSFixtureMachO(true)
			test.mutate(b)
			if _, err := convertDecryptedMachO(b); err == nil {
				t.Fatal("overwrote data")
			}
		})
	}
}

func macOSFixtureIPA(t *testing.T, extra map[string][]byte) string {
	t.Helper()
	info, _ := plist.Marshal(map[string]any{"CFBundleExecutable": "Example", "CFBundleIdentifier": "org.example.synthetic", "LSRequiresIPhoneOS": true}, plist.XMLFormat)
	entries := map[string][]byte{"Payload/Example.app/Info.plist": info, "Payload/Example.app/Example": macOSFixtureMachO(false), "Payload/Example.app/resource.txt": []byte("resource"), "Payload/Example.app/SC_Info/Example.sinf": []byte("synthetic"), "Payload/Example.app/Watch/Unsupported.app/binary": []byte("watch")}
	for name, data := range extra {
		entries[name] = data
	}
	filename := filepath.Join(t.TempDir(), "synthetic.ipa")
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for name, data := range entries {
		w, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return filename
}

func TestDecryptedIPAConversion(t *testing.T) {
	input := macOSFixtureIPA(t, map[string][]byte{"Payload/Example.app/Frameworks/Test.framework/Test": macOSFixtureMachO(false), "Payload/Example.app/Frameworks/Test.framework/Info.plist": []byte("synthetic signing stub")})
	output := filepath.Join(t.TempDir(), "Example.app")
	var calls [][]string
	signer := func(_ context.Context, args ...string) error {
		calls = append(calls, append([]string{}, args...))
		return nil
	}
	result, err := convertDecryptedIPA(context.Background(), MacOSAppOptions{input, output}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if result.ConvertedImages != 2 || !result.SignatureVerified || result.RuntimeVerified {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(calls) != 5 || !strings.Contains(calls[2][len(calls[2])-1], "Test.framework") || calls[4][0] != "--verify" {
		t.Fatalf("signing order: %v", calls)
	}
	for _, name := range []string{"SC_Info", "Watch"} {
		if _, err := os.Stat(filepath.Join(output, name)); !os.IsNotExist(err) {
			t.Fatalf("retained %s", name)
		}
	}
	data, err := os.ReadFile(filepath.Join(output, "Info.plist"))
	if err != nil {
		t.Fatal(err)
	}
	var info map[string]any
	if _, err := plist.Unmarshal(data, &info); err != nil {
		t.Fatal(err)
	}
	if _, ok := info["LSRequiresIPhoneOS"]; ok || info["LSMinimumSystemVersion"] != "11.0" {
		t.Fatal("incorrect metadata")
	}
	if _, err := convertDecryptedIPA(context.Background(), MacOSAppOptions{input, output}, signer); err == nil {
		t.Fatal("replaced existing app")
	}
}

func TestDecryptedIPAFailsWithoutPublishing(t *testing.T) {
	for _, test := range []struct {
		name     string
		extra    map[string][]byte
		signFail bool
	}{
		{"traversal", map[string][]byte{"../escape": {}}, false},
		{"case collision", map[string][]byte{"Payload/Example.app/RESOURCE.txt": {}}, false},
		{"multiple apps", map[string][]byte{"Payload/Other.app/Info.plist": {}}, false},
		{"missing main", map[string][]byte{"Payload/Example.app/Example": []byte("text")}, false},
		{"bad plist", map[string][]byte{"Payload/Example.app/Info.plist": []byte("invalid")}, false},
		{"sign failure", nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := macOSFixtureIPA(t, test.extra)
			output := filepath.Join(t.TempDir(), "Example.app")
			signer := func(context.Context, ...string) error {
				if test.signFail {
					return fmt.Errorf("synthetic signing failure")
				}
				return nil
			}
			if _, err := convertDecryptedIPA(context.Background(), MacOSAppOptions{input, output}, signer); err == nil {
				t.Fatal("accepted bad conversion")
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatal("published failed conversion")
			}
			entries, _ := os.ReadDir(filepath.Dir(output))
			if len(entries) != 0 {
				t.Fatal("left staging files")
			}
		})
	}
}

func TestMacOSMemberNames(t *testing.T) {
	for _, name := range []string{"../escape", "/absolute", "Payload/../escape", "Payload//App.app/a", "Payload/./App.app/a", "C:\\escape", "Payload/App.app/a\x00b"} {
		if _, err := macOSMemberName(name); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
}

func TestMacOSSwiftUIKitRewrite(t *testing.T) {
	for _, kind := range []uint32{0xc, 0x80000018} {
		b := macOSFixtureMachO(false)
		command := make([]byte, 56)
		binary.LittleEndian.PutUint32(command[:4], kind)
		binary.LittleEndian.PutUint32(command[4:8], uint32(len(command)))
		binary.LittleEndian.PutUint32(command[8:12], 24)
		copy(command[24:], "@rpath/libswiftUIKit.dylib")
		copy(b[232:], command)
		binary.LittleEndian.PutUint32(b[16:20], 4)
		binary.LittleEndian.PutUint32(b[20:24], 256)
		out, err := convertDecryptedMachO(b)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(out[:512], []byte("/System/iOSSupport/usr/lib/swift/libswiftUIKit.dylib\x00")) {
			t.Fatal("missing rewritten Swift UIKit dependency")
		}
		if !bytes.Equal(out[512:], b[512:]) {
			t.Fatal("changed code")
		}
		binary.LittleEndian.PutUint32(b[240:244], 56)
		if _, err := convertDecryptedMachO(b); err == nil {
			t.Fatal("accepted invalid dylib name offset")
		}
	}
}

func TestMacOSUniversalSelection(t *testing.T) {
	thin := macOSFixtureMachO(false)
	fat := make([]byte, 2048)
	binary.BigEndian.PutUint32(fat[:4], fatMagic)
	binary.BigEndian.PutUint32(fat[4:8], 1)
	binary.BigEndian.PutUint32(fat[8:12], cpuTypeARM64)
	binary.BigEndian.PutUint32(fat[16:20], 1024)
	binary.BigEndian.PutUint32(fat[20:24], uint32(len(thin)))
	binary.BigEndian.PutUint32(fat[24:28], 10)
	copy(fat[1024:], thin)
	out, err := convertDecryptedMachO(fat)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(thin) || binary.LittleEndian.Uint32(out[:4]) != mhMagic64 {
		t.Fatal("did not thin arm64 image")
	}
}

func TestMacOSRejectsArchiveSymlink(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "symlink.ipa")
	f, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	h := &zip.FileHeader{Name: "Payload/Example.app/link"}
	h.SetMode(os.ModeSymlink | 0o777)
	w, err := z.CreateHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("/outside")); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "Example.app")
	if _, err := convertDecryptedIPA(context.Background(), MacOSAppOptions{filename, output}, func(context.Context, ...string) error { return nil }); err == nil {
		t.Fatal("accepted symlink")
	}
}

func TestMacOSPreservesMinimumVersion(t *testing.T) {
	b := macOSFixtureMachO(false)
	binary.LittleEndian.PutUint32(b[196:200], 18<<16)
	binary.LittleEndian.PutUint32(b[200:204], 18<<16)
	out, err := convertDecryptedMachO(b)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(out[196:200]) != 18<<16 {
		t.Fatal("lowered required OS version")
	}
}
