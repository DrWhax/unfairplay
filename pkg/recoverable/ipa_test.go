package recoverable

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestModelSelectionRejectsAmbiguityAndSymlinks(t *testing.T) {
	d := t.TempDir()
	os.Chmod(d, 0700)
	if _, e := SelectModel(d); e == nil {
		t.Fatal("empty registry accepted")
	}
	a := filepath.Join(d, "a.bin")
	os.WriteFile(a, []byte("fixture"), 0600)
	if p, e := SelectModel(d); e != nil || p != a {
		t.Fatal("unique model not selected")
	}
	b := filepath.Join(d, "b.bin")
	os.WriteFile(b, []byte("fixture"), 0600)
	if _, e := SelectModel(d); e == nil {
		t.Fatal("ambiguous registry accepted")
	}
	os.Remove(b)
	os.Symlink(a, b)
	if _, e := SelectModel(d); e == nil {
		t.Fatal("symlink accepted")
	}
}
func TestExistingOutputPreserved(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "out.ipa")
	want := []byte("existing")
	os.WriteFile(p, want, 0600)
	for _, f := range []func(Options) (Result, error){Decrypt, Encrypt} {
		if _, e := f(Options{InputPath: "input.ipa", OutputPath: p}); e == nil {
			t.Fatal("existing output accepted")
		}
		got, _ := os.ReadFile(p)
		if !bytes.Equal(got, want) {
			t.Fatal("existing output modified")
		}
	}
}
func TestRejectMalformedAtoms(t *testing.T) {
	for _, b := range [][]byte{{}, {0}, {0, 0, 0, 7, 't', 'e', 's', 't'}, {0, 0, 0, 9, 't', 'e', 's', 't'}} {
		if _, e := fields(b); e == nil {
			t.Fatal("malformed license accepted")
		}
	}
}

func TestModelFileBoundsAndPermutation(t *testing.T) {
	valid := syntheticModel()
	for _, tc := range []struct {
		name  string
		data  []byte
		valid bool
	}{
		{"valid", valid, true},
		{"truncated", valid[:len(valid)-1], false},
		{"oversized", append(bytes.Clone(valid), 0), false},
		{"invalid permutation", make([]byte, len(valid)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "invalid permutation" {
				copy(tc.data, valid)
				tc.data[89] = tc.data[88]
			}
			p := filepath.Join(t.TempDir(), "model.bin")
			if err := os.WriteFile(p, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			got, err := model(p)
			defer clear(got)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}
