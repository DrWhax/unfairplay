package recovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DrWhax/unfairplay/pkg/fairplay"
)

func TestAccountClassKeyNativeOracle(t *testing.T) {
	capture, oracle := os.Getenv("UNFAIRPLAY_TEST_CAPTURE"), os.Getenv("UNFAIRPLAY_CLASS_OPERANDS_ORACLE")
	if capture == "" || oracle == "" {
		t.Skip("private native inputs not configured")
	}
	manifest, err := fairplay.LoadEnrollmentCapture(capture, true)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := fairplay.NormalizeEnrollmentCapture(capture, manifest)
	if err != nil {
		t.Fatal(err)
	}
	hardware, err := readPrivateInput(canonical.PrivateHardwarePath())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(hardware)
	fileMappings, _ := canonical.RuntimeFileMappings()
	var sinf []byte
	for _, mapping := range fileMappings {
		name, path, ok := strings.Cut(mapping, "=")
		if ok && filepath.Ext(name) == ".sinf" {
			sinf, err = readPrivateInput(path)
			if err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if len(sinf) == 0 {
		t.Fatal("private capture has no installed SINF")
	}
	defer clear(sinf)
	user, keyID, err := enrollmentSINFSelector(sinf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := accountClassKey(hardware, user, keyID)
	if err != nil {
		t.Fatal(err)
	}
	want, err := readPrivateInput(oracle)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(want)
	if len(want) < 16 {
		t.Fatal("native operand oracle too short")
	}
	for i := range got {
		if got[i] != want[i]^0x1b {
			t.Fatal("derived class key differs from native operand")
		}
	}
	t.Log("derived class key matches native class join operand")
}
