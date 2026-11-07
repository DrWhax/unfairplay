package recovery

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/DrWhax/unfairplay/pkg/fairplay"
)

// TestSIDBNativeSourceAndBodyOracle compares the production native-exit path
// with external, private native-reference outputs. It neither imports an existing
// enrollment model nor exports keys or decoded input.
func TestSIDBNativeSourceAndBodyOracle(t *testing.T) {
	capture := os.Getenv("UNFAIRPLAY_TEST_CAPTURE")
	sourceOracle := os.Getenv("UNFAIRPLAY_SIDB_SOURCE_ORACLE")
	bodyOracle := os.Getenv("UNFAIRPLAY_SIDB_BODY_ORACLE")
	if capture == "" || sourceOracle == "" || bodyOracle == "" {
		t.Skip("private capture and native oracle files not configured")
	}
	manifest, err := fairplay.LoadEnrollmentCapture(capture, true)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := fairplay.NormalizeEnrollmentCapture(capture, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(canonical.SIDBs) != 1 {
		t.Fatal("oracle comparison requires one SIDB")
	}
	container, err := readPrivateInput(filepath.Join(capture, canonical.SIDBs[0].File.CapturePath))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(container)
	hardware, err := readPrivateInput(canonical.PrivateHardwarePath())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(hardware)
	expectedSource, err := readPrivateInput(sourceOracle)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(expectedSource)
	expectedBody, err := readPrivateInput(bodyOracle)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(expectedBody)

	source, layout, _, err := deriveNativeSelectionSource(container, hardware)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(source)
	if len(source) != layout.SourceBytes || layout.SourceBytes < selectionSourcePrefixBytes || len(expectedSource) < layout.SourceBytes || !bytes.Equal(source, expectedSource[:layout.SourceBytes]) {
		t.Fatal("complete selection source differs from native oracle")
	}
	projected, err := decodeSelectionSIDBContainerWithLayout(container, layout)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(projected)
	key, err := deriveSelectedEnrollmentKey(source[selectionSourcePrefixBytes:layout.SourceBytes], layout.SelectedSlot)
	if err != nil {
		t.Fatal("cannot derive selected native key")
	}
	body, err := decryptSelectionSIDBPayloadDynamic(projected, key)
	clear(key[:])
	if err != nil {
		t.Fatal("cannot decode selected body")
	}
	defer clear(body)
	if !bytes.Equal(body, expectedBody) {
		t.Fatal("native selected body differs from oracle")
	}
	if _, err := parseDecodedSIDBRegistry(expectedBody, layout.RootCursor); err != nil {
		t.Fatalf("native decoded body fails production grammar: %v", err)
	}
	t.Log("native source and body match")
}
