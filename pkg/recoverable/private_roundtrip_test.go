package recoverable

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	zipmaps "maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	f "github.com/DrWhax/unfairplay/pkg/fairplay"
)

// TestPrivateRecoveryRoundTrip is opt-in and contains no private fixture data.
func TestPrivateRecoveryRoundTrip(t *testing.T) {
	manifest := os.Getenv("UNFAIRPLAY_RECOVERY_CONTROLS")
	if manifest == "" {
		t.Skip("private controls not configured")
	}
	var controls []struct{ Source, Enhanced, Encrypted, Converted, SourceModel, TargetModel string }
	b, e := os.ReadFile(manifest)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &controls); e != nil {
		t.Fatal(e)
	}
	if len(controls) == 0 {
		t.Fatal("empty controls")
	}
	for _, c := range controls {
		func() {
			zs := []*zip.ReadCloser{}
			maps := []map[string]*zip.File{}
			for _, p := range []string{c.Source, c.Enhanced, c.Encrypted, c.Converted} {
				z, e := zip.OpenReader(p)
				if e != nil {
					t.Fatal("open control")
				}
				defer z.Close()
				zs = append(zs, z)
				m, e := members(z)
				if e != nil {
					t.Fatal(e)
				}
				maps = append(maps, m)
			}
			rp, e := recoveryMemberPath(maps[1])
			if e != nil {
				t.Fatal(e)
			}
			if maps[1][rp] == nil {
				t.Fatal("missing unified material")
			}
			count := 0
			for n := range maps[1] {
				if strings.HasSuffix(n, recoverySuffix) {
					count++
				}
				if filepath.Base(n) == "AppContentKey.bin" || filepath.Base(n) == "AppRecovery.json" {
					t.Fatal("legacy files present")
				}
			}
			if count != 1 {
				t.Fatal("not one recovery file")
			}
			capsule, e := read(maps[1][rp])
			if e != nil {
				t.Fatal(e)
			}
			metadata, e := decodeMetadata(capsule)
			if e != nil {
				t.Fatal(e)
			}
			defer metadata.clearSecrets()
			sp := strings.TrimSuffix(rp, "-recovery")
			for i, mp := range []string{c.SourceModel, c.TargetModel} {
				mp, e = SelectModel(mp)
				if e != nil {
					t.Fatal(e)
				}
				p, e := model(mp)
				if e != nil {
					t.Fatal(e)
				}
				index := 0
				if i == 1 {
					index = 2
				}
				if maps[index][sp] == nil {
					t.Fatal("license route missing")
				}
				sinf, e := read(maps[index][sp])
				if e != nil {
					t.Fatal(e)
				}
				shared, e := extractMetadata(sinf, p)
				clear(p)
				if e != nil {
					t.Fatal(e)
				}
				if !reflect.DeepEqual(shared, metadata) {
					t.Fatal("shared source fields changed")
				}
				shared.clearSecrets()
			}
			for _, index := range []int{2, 3} {
				for n := range maps[index] {
					if strings.HasSuffix(n, recoverySuffix) || filepath.Base(n) == "AppContentKey.bin" || filepath.Base(n) == "AppRecovery.json" {
						t.Fatal("recovery material leaked to encrypted output")
					}
				}
			}
			sourceMembers := zipmaps.Clone(maps[0])
			if err := f.OmitAppleDoubleSidecars(sourceMembers); err != nil {
				t.Fatal(err)
			}
			for n := range maps[0] {
				if sourceMembers[n] != nil {
					continue
				}
				for i := 1; i < 4; i++ {
					if maps[i][n] != nil {
						t.Fatal("AppleDouble sidecar retained")
					}
				}
			}
			for n, v := range sourceMembers {
				b, e := read(v)
				if e != nil {
					t.Fatal(e)
				}
				isMach := len(b) >= 4 && (bytes.Equal(b[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}) || bytes.Equal(b[:4], []byte{0xce, 0xfa, 0xed, 0xfe}) || bytes.Equal(b[:4], []byte{0xca, 0xfe, 0xba, 0xbe}))
				isPage := strings.HasSuffix(n, ".supf") || strings.HasSuffix(n, ".supp") || strings.HasSuffix(n, ".supx")
				if isMach || isPage {
					for _, i := range []int{2, 3} {
						if maps[i][n] == nil {
							t.Fatal("missing source member")
						}
						other, e := read(maps[i][n])
						if e != nil || !bytes.Equal(b, other) {
							t.Fatal("binary/page material changed")
						}
					}
				}
				if isPage {
					if maps[1][n] == nil {
						t.Fatal("missing page file")
					}
					other, e := read(maps[1][n])
					if e != nil || !bytes.Equal(b, other) {
						t.Fatal("page file changed in enhanced output")
					}
				}
			}
			protected, e := f.UnencryptedBundles(c.Source)
			if e != nil {
				t.Fatal(e)
			}
			for _, prefix := range protected {
				for i := 1; i < 4; i++ {
					for n, v := range maps[0] {
						if !strings.HasPrefix(n, prefix) {
							continue
						}
						other := maps[i][n]
						if other == nil {
							t.Fatal("inert component member removed")
						}
						a, _ := read(v)
						b, _ := read(other)
						if !bytes.Equal(a, b) || v.ExternalAttrs != other.ExternalAttrs || v.ModifiedDate != other.ModifiedDate || v.ModifiedTime != other.ModifiedTime {
							t.Fatal("inert component changed")
						}
					}
					for n := range maps[i] {
						if strings.HasPrefix(n, prefix) && maps[0][n] == nil {
							t.Fatal("inert component member added")
						}
					}
				}
			}
		}()
	}
}
