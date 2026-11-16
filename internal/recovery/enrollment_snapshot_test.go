package recovery

import (
	"bytes"
	"context"
	"testing"

	"github.com/DrWhax/unfairplay/pkg/fairplay"
)

func syntheticSnapshotRecovery(t *testing.T) (fairplay.EnrollmentSnapshot, []byte, [16]byte) {
	t.Helper()
	container, hardware, layout := syntheticNativeSIDB(t, selectionSIDBPayloadBytes)
	source, _, _, err := deriveNativeSelectionSource(container, hardware)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(source)
	key, err := deriveSelectedEnrollmentKey(source[selectionSourcePrefixBytes:], layout.SelectedSlot)
	if err != nil {
		t.Fatal(err)
	}
	body, _, sinf, _, _, precursor := syntheticProductionRoute(t, hardware, selectionSIDBPayloadBytes)
	fillSyntheticSelectionSIDBContainer(t, container, layout.PayloadOffset, body, key)
	sealSyntheticSelectionContainer(t, container, source)
	snapshot := fairplay.EnrollmentSnapshot{SIDB: container, ProductVersion: "26.0", BuildVersion: "synthetic"}
	copy(snapshot.Hardware[:], hardware)
	return snapshot, sinf, precursor
}

func TestSnapshotRecoveryWithoutInstalledApp(t *testing.T) {
	snapshot, sinf, precursor := syntheticSnapshotRecovery(t)
	defer snapshot.Clear()
	encoded, err := snapshot.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := fairplay.ParseEnrollmentSnapshot(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Clear()
	if err := ValidateEnrollmentSnapshot(context.Background(), parsed); err != nil {
		t.Fatal(err)
	}
	selector, err := fairplay.ParseSINFSelector(sinf)
	if err != nil {
		t.Fatal(err)
	}
	keyfile, authority := syntheticSignedSUPF(t, 5)
	licenses := fairplay.IPAEnrollmentInputs{Selector: selector, Files: map[string][]byte{"selected.sinf": sinf, "Payload/Test.app/SC_Info/Test.v5.supf": keyfile}}
	inputs, err := snapshotRecoveryInputs(parsed, licenses)
	if err != nil {
		t.Fatal(err)
	}
	// A test CA signs the synthetic page-key file. Production cannot select it.
	got, err := recoverCurrentInputs(context.Background(), inputs, nil, authority)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got.EnrollmentModel)
	want, err := enrollmentPackForPrecursor(typedEnrollmentAlgorithmIdentity, selector.User, selector.Key, precursor)
	if err != nil || !bytes.Equal(want, got.EnrollmentModel) {
		t.Fatal("snapshot recovery changed the model", err)
	}
	material, err := fairplay.ResolveLogicalKeyWithModel(sinf, got.EnrollmentModel)
	if err != nil || material.LogicalKey == [16]byte{} {
		t.Fatal("recovered model did not decode target SINF", err)
	}
	if _, err := RecoverEnrollmentSnapshot(context.Background(), parsed, licenses, nil); err == nil {
		t.Fatal("production accepted synthetic signing authority")
	}
	keyfile[len(keyfile)-1] ^= 1
	if _, err := recoverCurrentInputs(context.Background(), inputs, nil, authority); err == nil {
		t.Fatal("accepted damaged signed envelope")
	}
	keyfile[len(keyfile)-1] ^= 1
	priv, err := currentSINFPrivateSource(sinf)
	if err != nil {
		t.Fatal(err)
	}
	priv[32] ^= 1
	if _, err := recoverCurrentInputs(context.Background(), inputs, nil, authority); err == nil {
		t.Fatal("accepted wrong SINF private payload")
	}
}

func TestSnapshotRecoveryRejectsInvalidState(t *testing.T) {
	snapshot, sinf, _ := syntheticSnapshotRecovery(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ValidateEnrollmentSnapshot(ctx, snapshot); err == nil {
		t.Fatal("ignored cancellation")
	}
	if _, err := RecoverEnrollmentSnapshot(ctx, snapshot, fairplay.IPAEnrollmentInputs{}, nil); err == nil {
		t.Fatal("ignored recovery cancellation")
	}
	for _, index := range []int{0, len(snapshot.SIDB) - 1} {
		bad := snapshot
		bad.SIDB = bytes.Clone(snapshot.SIDB)
		bad.SIDB[index] ^= 1
		if err := ValidateEnrollmentSnapshot(context.Background(), bad); err == nil {
			t.Fatal("accepted corrupt SIDB")
		}
	}
	bad := snapshot
	bad.Hardware[0] ^= 1
	if err := ValidateEnrollmentSnapshot(context.Background(), bad); err == nil {
		t.Fatal("accepted wrong hardware")
	}
	for _, name := range []string{"SC Info.sidb", "nested/SC Info.sidb", "unexpected.bin"} {
		licenses := fairplay.IPAEnrollmentInputs{Files: map[string][]byte{name: {1}}}
		if _, err := snapshotRecoveryInputs(snapshot, licenses); err == nil {
			t.Fatal("accepted state supplied as an IPA license")
		}
	}
	selector, err := fairplay.ParseSINFSelector(sinf)
	if err != nil {
		t.Fatal(err)
	}
	licenses := fairplay.IPAEnrollmentInputs{Selector: selector, Files: map[string][]byte{"selected.sinf": sinf}}
	if _, err := RecoverEnrollmentSnapshot(context.Background(), snapshot, licenses, nil); err == nil {
		t.Fatal("accepted missing signed key file")
	}
	licenses.Selector.Key ^= 1
	if _, err := snapshotRecoveryInputs(snapshot, licenses); err == nil {
		t.Fatal("accepted selector mismatch")
	}
	licenses.Selector = selector
	licenses.Files["another.sinf"] = sinf
	if _, err := snapshotRecoveryInputs(snapshot, licenses); err == nil {
		t.Fatal("accepted ambiguous SINF inputs")
	}
	delete(licenses.Files, "another.sinf")
	licenses.Files["selected.sinf"] = []byte("malformed")
	if _, err := snapshotRecoveryInputs(snapshot, licenses); err == nil {
		t.Fatal("accepted malformed SINF")
	}
	delete(licenses.Files, "selected.sinf")
	if _, err := snapshotRecoveryInputs(snapshot, licenses); err == nil {
		t.Fatal("accepted absent SINF")
	}
}
