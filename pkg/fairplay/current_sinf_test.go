package fairplay

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

type syntheticSINFFixture struct {
	sinf     []byte
	private  []byte
	innerKey [16]byte
	logical  [16]byte
	selector SINFSelector
}

func testAtom(typ string, payload []byte) []byte {
	result := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(result[:4], uint32(len(result)))
	copy(result[4:8], typ)
	copy(result[8:], payload)
	return result
}

func syntheticLegacyModel() currentSINFModel {
	model := currentSINFModel{version: 1}
	for index := range model.modelIdentity {
		model.modelIdentity[index] = byte(index + 1)
	}
	model.key = [16]byte{0x61, 0x19, 0xe4, 0x72, 0x0b, 0xce, 0x35, 0xa8, 0xd7, 0x43, 0x9a, 0xf0, 0x26, 0x58, 0xbd, 0x8c}
	model.whitening = [16]byte{0x11, 0x23, 0x35, 0x47, 0x59, 0x6b, 0x7d, 0x8f, 0x90, 0xa2, 0xb4, 0xc6, 0xd8, 0xea, 0xfc, 0x0e}
	for position := 0; position < 16; position++ {
		for value := 0; value < 256; value++ {
			model.inputDecode[position*256+value] = byte(value) ^ byte(position*17)
		}
	}
	return model
}

func legacyModelPack(model currentSINFModel) []byte {
	pack := make([]byte, currentSINFModelV1Bytes)
	copy(pack[:8], enrollmentModelV1Magic)
	binary.LittleEndian.PutUint32(pack[8:12], 1)
	binary.LittleEndian.PutUint32(pack[12:16], uint32(len(pack)))
	copy(pack[16:48], model.modelIdentity[:])
	copy(pack[48:64], model.key[:])
	copy(pack[64:80], model.whitening[:])
	copy(pack[80:], model.inputDecode[:])
	return pack
}

func syntheticCurrentSINFFixture(t *testing.T, user, key uint32, righBytes int, innerKey [16]byte) syntheticSINFFixture {
	t.Helper()
	model := syntheticLegacyModel()

	types := [...]string{"key ", "iviv", "tmpr", "righ", "name"}
	sizes := [...]int{24, 24, 24, righBytes, 264}
	plaintext := make([]byte, 0, 432)
	var visibleIVIV, visibleRights, visibleName []byte
	for index, typ := range types {
		atom := make([]byte, sizes[index])
		binary.BigEndian.PutUint32(atom[:4], uint32(len(atom)))
		copy(atom[4:8], typ)
		if index == 0 {
			copy(atom[8:], innerKey[:])
		}
		if typ == "righ" {
			for rightIndex, name := range currentSINFRequiredRights {
				copy(atom[8+rightIndex*8:8+rightIndex*8+4], name)
			}
			if len(atom)-8 >= 88 {
				copy(atom[8+9*8:8+9*8+4], "hi32")
			}
			if len(atom)-8 >= 96 {
				copy(atom[8+10*8:8+10*8+4], "xtra")
			}
			visibleRights = append([]byte(nil), atom[8:]...)
		}
		if typ == "iviv" {
			visibleIVIV = append([]byte(nil), atom[8:]...)
		}
		if typ == "name" {
			copy(atom[8:], "Synthetic")
			visibleName = append([]byte(nil), atom[8:]...)
		}
		plaintext = append(plaintext, atom...)
	}

	trailerBytes := len(plaintext) % aes.BlockSize
	ciphertextBytes := len(plaintext) - trailerBytes
	iv := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	block, err := aes.NewCipher(model.key[:])
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, ciphertextBytes)
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(ciphertext, plaintext[:ciphertextBytes])
	logicalPayload := append(append([]byte(nil), iv[:]...), ciphertext...)
	protected := make([]byte, len(logicalPayload)+trailerBytes)
	for index, value := range logicalPayload {
		position := index % aes.BlockSize
		external := -1
		for candidate, decoded := range model.inputDecode[position*256 : (position+1)*256] {
			if decoded == value {
				external = candidate
				break
			}
		}
		if external < 0 {
			t.Fatalf("input table %d cannot encode %#x", position, value)
		}
		protected[index] = byte(external) ^ model.whitening[position]
	}

	userPayload := make([]byte, 4)
	keyPayload := make([]byte, 4)
	binary.BigEndian.PutUint32(userPayload, user)
	binary.BigEndian.PutUint32(keyPayload, key)
	fields := append(testAtom("user", userPayload), testAtom("key ", keyPayload)...)
	fields = append(fields, testAtom("iviv", visibleIVIV)...)
	fields = append(fields, testAtom("righ", visibleRights)...)
	fields = append(fields, testAtom("name", visibleName)...)
	fields = append(fields, testAtom("priv", protected)...)
	sinf := testAtom("sinf", testAtom("schi", fields))

	return syntheticSINFFixture{
		sinf: sinf, private: protected, innerKey: innerKey,
		logical: logicalFromInnerKey(innerKey), selector: SINFSelector{User: user, Key: key},
	}
}

func selectorBoundModelPack(t *testing.T, selector SINFSelector) []byte {
	t.Helper()
	model := syntheticLegacyModel()
	pack := make([]byte, currentSINFModelV2Bytes)
	copy(pack[:8], enrollmentModelV2Magic)
	binary.LittleEndian.PutUint32(pack[8:12], 2)
	binary.LittleEndian.PutUint32(pack[12:16], uint32(len(pack)))
	copy(pack[16:48], model.modelIdentity[:])
	binary.LittleEndian.PutUint32(pack[48:52], selector.User)
	binary.LittleEndian.PutUint32(pack[52:56], selector.Key)
	copy(pack[56:72], model.key[:])
	copy(pack[72:88], model.whitening[:])
	copy(pack[88:], model.inputDecode[:])
	return pack
}

func syntheticCurrentSINFV3Fixture(t *testing.T, selector SINFSelector, innerKey [16]byte) ([]byte, []byte) {
	t.Helper()
	private := make([]byte, 440)
	for index := range private {
		private[index] = byte(index*29 + 7)
	}
	userPayload := make([]byte, 4)
	keyPayload := make([]byte, 4)
	binary.BigEndian.PutUint32(userPayload, selector.User)
	binary.BigEndian.PutUint32(keyPayload, selector.Key)
	fields := append(testAtom("user", userPayload), testAtom("key ", keyPayload)...)
	fields = append(fields, testAtom("iviv", make([]byte, 16))...)
	fields = append(fields, testAtom("righ", make([]byte, 80))...)
	fields = append(fields, testAtom("name", make([]byte, 256))...)
	fields = append(fields, testAtom("priv", private)...)
	children := append(testAtom("frma", []byte("game")), testAtom("schm", make([]byte, 12))...)
	children = append(children, testAtom("schi", fields)...)
	children = append(children, testAtom("sign", make([]byte, 128))...)
	sinf := testAtom("sinf", children)

	plaintext := make([]byte, currentSINFV3SourceBytes)
	copy(plaintext[0:4], "itun")
	binary.BigEndian.PutUint32(plaintext[4:8], 12)
	copy(plaintext[8:12], "vers")
	binary.BigEndian.PutUint32(plaintext[12:16], 1)
	fieldsV3 := [...]struct {
		offset int
		size   uint32
		typ    string
	}{
		{16, 24, "key "},
		{40, 24, "iviv"},
		{64, 24, "tmpr"},
		{88, 88, "righ"},
		{176, 264, "name"},
	}
	for _, field := range fieldsV3 {
		binary.BigEndian.PutUint32(plaintext[field.offset:field.offset+4], field.size)
		copy(plaintext[field.offset+4:field.offset+8], field.typ)
	}
	copy(plaintext[24:40], innerKey[:])

	pack := make([]byte, currentSINFModelV3Bytes)
	copy(pack[:8], enrollmentModelV3Magic)
	binary.LittleEndian.PutUint32(pack[8:12], 3)
	binary.LittleEndian.PutUint32(pack[12:16], uint32(len(pack)))
	for index := 16; index < 48; index++ {
		pack[index] = byte(index)
	}
	binary.LittleEndian.PutUint32(pack[48:52], selector.User)
	binary.LittleEndian.PutUint32(pack[52:56], selector.Key)
	binary.LittleEndian.PutUint32(pack[60:64], currentSINFV3SourceBytes)
	pack[64] = 0x98
	aesKey := [16]byte{0x61, 0x19, 0xe4, 0x72, 0x0b, 0xce, 0x35, 0xa8, 0xd7, 0x43, 0x9a, 0xf0, 0x26, 0x58, 0xbd, 0x8c}
	copy(pack[68:84], aesKey[:])
	cursor := 84
	for table := 0; table < 16; table++ {
		for value := 0; value < 256; value++ {
			pack[cursor+table*256+value] = byte(value)
		}
	}
	cursor += 16 * 256

	parsedFields, err := parseSINFFields(sinf)
	if err != nil {
		t.Fatal(err)
	}
	privateAtom, err := uniqueAtom(parsedFields, "priv")
	if err != nil {
		t.Fatal(err)
	}
	sourceOffset := privateAtom.start + 24
	binary.LittleEndian.PutUint32(pack[56:60], uint32(sourceOffset))
	source := sinf[sourceOffset : sourceOffset+currentSINFV3SourceBytes]
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		t.Fatal(err)
	}
	internal := make([]byte, len(source))
	for offset := 0; offset < len(source); offset += aes.BlockSize {
		block.Decrypt(internal[offset:offset+aes.BlockSize], source[offset:offset+aes.BlockSize])
	}
	for index := range internal {
		pack[cursor+index] = internal[index] ^ plaintext[index] ^ pack[64]
	}
	cursor += currentSINFV3SourceBytes
	for table := 0; table < 16; table++ {
		for value := 0; value < 256; value++ {
			pack[cursor+table*256+value] = byte(value)
		}
	}
	return sinf, pack
}

func TestCurrentSINFModelV3SyntheticRoundTrip(t *testing.T) {
	selector := SINFSelector{User: 0x11223344, Key: 2}
	innerKey := [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01}
	sinf, pack := syntheticCurrentSINFV3Fixture(t, selector, innerKey)
	material, err := ResolveLogicalKeyWithModel(sinf, pack)
	if err != nil {
		t.Fatal(err)
	}
	if want := logicalFromInnerKey(innerKey); material.LogicalKey != want {
		t.Fatalf("logical key changed: %x", material.LogicalKey)
	}
	if material.Evidence["provider_kind"] != "current-sinf-whitebox-direct-v3" || material.Evidence["model_version"] != uint32(3) {
		t.Fatalf("unexpected version 3 evidence: %#v", material.Evidence)
	}
}

func TestCurrentSINFModelV3RegistrySelection(t *testing.T) {
	selector := SINFSelector{User: 0x11223344, Key: 2}
	innerKey := [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01}
	sinf, matching := syntheticCurrentSINFV3Fixture(t, selector, innerKey)
	other := selectorBoundModelPack(t, SINFSelector{User: 0x55667788, Key: 2})
	material, err := ResolveLogicalKeyWithModels(sinf, [][]byte{other, matching})
	if err != nil {
		t.Fatal(err)
	}
	if want := logicalFromInnerKey(innerKey); material.LogicalKey != want {
		t.Fatalf("logical key changed: %x", material.LogicalKey)
	}
}

func TestCurrentSINFModelV3Validation(t *testing.T) {
	selector := SINFSelector{User: 0x11223344, Key: 2}
	innerKey := [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01}
	sinf, pack := syntheticCurrentSINFV3Fixture(t, selector, innerKey)

	reserved := append([]byte(nil), pack...)
	reserved[65] = 1
	if _, err := parseCurrentSINFModel(reserved); err == nil {
		t.Fatal("nonzero version 3 reserved byte was accepted")
	}
	for name, offset := range map[string]int{
		"output":     84,
		"post-codec": 84 + 16*256 + currentSINFV3SourceBytes,
	} {
		t.Run(name, func(t *testing.T) {
			mutated := append([]byte(nil), pack...)
			mutated[offset] = mutated[offset+1]
			if _, err := parseCurrentSINFModel(mutated); err == nil {
				t.Fatal("corrupt version 3 model was accepted")
			}
		})
	}

	badBounds := append([]byte(nil), pack...)
	binary.LittleEndian.PutUint32(badBounds[56:60], uint32(len(sinf)))
	if _, err := ResolveLogicalKeyWithModel(sinf, badBounds); !errors.Is(err, errCurrentSINFProfileMismatch) {
		t.Fatalf("invalid version 3 source bounds returned %v", err)
	}

	mutatedSINF := append([]byte(nil), sinf...)
	parsedFields, err := parseSINFFields(mutatedSINF)
	if err != nil {
		t.Fatal(err)
	}
	privateAtom, err := uniqueAtom(parsedFields, "priv")
	if err != nil {
		t.Fatal(err)
	}
	mutatedSINF[privateAtom.start+24] ^= 1
	if _, err := ResolveLogicalKeyWithModel(mutatedSINF, pack); !errors.Is(err, errCurrentSINFProfileMismatch) {
		t.Fatalf("mutated version 3 SINF returned %v", err)
	}
}

func TestCurrentSINFModelV3ExternalFixture(t *testing.T) {
	modelPath := os.Getenv("UNFAIRPLAY_V3_MODEL")
	sinfPath := os.Getenv("UNFAIRPLAY_V3_SINF")
	expectedSHA256 := os.Getenv("UNFAIRPLAY_V3_LOGICAL_KEY_SHA256")
	if modelPath == "" && sinfPath == "" && expectedSHA256 == "" {
		t.Skip("private version 3 regression fixture is not configured")
	}
	if modelPath == "" || sinfPath == "" || len(expectedSHA256) != 64 {
		t.Fatal("private version 3 regression requires model, SINF, and logical-key SHA-256")
	}
	pack, err := os.ReadFile(modelPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pack)
	sinf, err := os.ReadFile(sinfPath)
	if err != nil {
		t.Fatal(err)
	}
	material, err := ResolveLogicalKeyWithModel(sinf, pack)
	if err != nil {
		t.Fatal(err)
	}
	if observed := digest(material.LogicalKey[:]); observed != expectedSHA256 {
		t.Fatalf("logical-key SHA-256 = %s, want %s", observed, expectedSHA256)
	}
}

func TestCurrentSINFModelSyntheticRoundTrip(t *testing.T) {
	model := syntheticLegacyModel()
	innerKey := [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01}
	fixture := syntheticCurrentSINFFixture(t, 0x10203040, 2, 88, innerKey)
	fields, err := parseSINFFields(fixture.sinf)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := currentSINFPrivateKey(model, fixture.sinf, fields)
	if err != nil {
		t.Fatal(err)
	}
	if observed != innerKey {
		t.Fatalf("inner key changed: %x", observed)
	}
	if gotLogical := logicalFromInnerKey(observed); gotLogical != fixture.logical {
		t.Fatalf("logical key changed: %x", gotLogical)
	}
}

func TestCurrentSINFModelValidation(t *testing.T) {
	model := syntheticLegacyModel()
	if model.key == [16]byte{} || model.whitening == [16]byte{} {
		t.Fatal("synthetic current SINF model is empty")
	}
	pack := legacyModelPack(model)
	for _, offset := range []int{0, 8, 12, 80, len(pack) - 1} {
		mutated := append([]byte(nil), pack...)
		mutated[offset] ^= 1
		if _, err := parseCurrentSINFModel(mutated); err == nil {
			t.Fatalf("model corruption at %#x was accepted", offset)
		}
	}
}

func TestExternalCurrentSINFModel(t *testing.T) {
	innerKey := [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01}
	fixture := syntheticCurrentSINFFixture(t, 0x10203040, 2, 88, innerKey)
	pack := legacyModelPack(syntheticLegacyModel())
	material, err := ResolveLogicalKeyWithModel(fixture.sinf, pack)
	if err != nil {
		t.Fatal(err)
	}
	if material.LogicalKey != fixture.logical {
		t.Fatalf("logical key changed: %x", material.LogicalKey)
	}
	if material.Evidence["state_origin"] != "external-enrollment-model" ||
		material.Evidence["model_sha256"] != digest(pack) {
		t.Fatalf("unexpected external-model evidence: %#v", material.Evidence)
	}
}

func TestSelectorBoundCurrentSINFModel(t *testing.T) {
	innerKey := [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01}
	fixture := syntheticCurrentSINFFixture(t, 0x10203040, 2, 88, innerKey)
	pack := selectorBoundModelPack(t, fixture.selector)
	material, err := ResolveLogicalKeyWithModel(fixture.sinf, pack)
	if err != nil {
		t.Fatal(err)
	}
	if material.LogicalKey != fixture.logical {
		t.Fatalf("logical key changed: %x", material.LogicalKey)
	}

	wrong := selectorBoundModelPack(t, SINFSelector{User: 0x50607080, Key: 2})
	if _, err := ResolveLogicalKeyWithModel(fixture.sinf, wrong); err == nil || !strings.Contains(err.Error(), fixture.selector.Identifier()) {
		t.Fatalf("selector mismatch was not rejected: %v", err)
	}
}

func TestCurrentSINFModelRegistry(t *testing.T) {
	innerKey := [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01}
	fixture := syntheticCurrentSINFFixture(t, 0x10203040, 2, 88, innerKey)
	other := selectorBoundModelPack(t, SINFSelector{User: 0x50607080, Key: 2})
	matching := selectorBoundModelPack(t, fixture.selector)
	material, err := ResolveLogicalKeyWithModels(fixture.sinf, [][]byte{other, matching})
	if err != nil {
		t.Fatal(err)
	}
	if material.LogicalKey != fixture.logical {
		t.Fatalf("logical key changed: %x", material.LogicalKey)
	}
	if _, err := ResolveLogicalKeyWithModels(fixture.sinf, [][]byte{other}); err == nil || !strings.Contains(err.Error(), "no model") {
		t.Fatalf("missing selector was not rejected: %v", err)
	}
	if _, err := ResolveLogicalKeyWithModels(fixture.sinf, [][]byte{matching, matching}); err == nil || !strings.Contains(err.Error(), "multiple models") {
		t.Fatalf("duplicate selector was not rejected: %v", err)
	}
	if _, err := ResolveLogicalKeyWithModels(fixture.sinf, [][]byte{legacyModelPack(syntheticLegacyModel())}); err == nil || !strings.Contains(err.Error(), "version 1") {
		t.Fatalf("unbound model was accepted in registry: %v", err)
	}
}

func TestCurrentSINFPortableFixtures(t *testing.T) {
	fixtures := []struct {
		name      string
		user, key uint32
		righBytes int
		innerKey  [16]byte
	}{
		{"zero-trailer", 0x11223344, 2, 96, [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}},
		{"eight-byte-trailer", 0x11223344, 2, 88, [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01}},
		{"extended-rights", 0x11223344, 2, 104, [16]byte{0x21, 0x43, 0x65, 0x87, 0xa9, 0xcb, 0xed, 0x0f, 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12}},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			input := syntheticCurrentSINFFixture(t, fixture.user, fixture.key, fixture.righBytes, fixture.innerKey)
			material, resolveErr := ResolveLogicalKeyWithModel(input.sinf, selectorBoundModelPack(t, input.selector))
			if resolveErr != nil {
				t.Fatal(resolveErr)
			}
			if !bytes.Equal(material.LogicalKey[:], input.logical[:]) {
				t.Fatal("portable current-SINF logical key differs from deterministic fixture")
			}
			if material.Evidence["provider_kind"] != "current-sinf-whitebox-direct-v1" ||
				material.Evidence["runtime_hardware_calls"] != 0 ||
				material.Evidence["request_selector"] != input.selector.Identifier() {
				t.Fatalf("unexpected evidence: %#v", material.Evidence)
			}
		})
	}
}

func TestCurrentSINFRejectsMutation(t *testing.T) {
	fixture := syntheticCurrentSINFFixture(t, 0x90a0b0c0, 7, 96, [16]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99})
	fields, err := parseSINFFields(fixture.sinf)
	if err != nil {
		t.Fatal(err)
	}
	private, err := sinfPrivatePayload(fixture.sinf, fields)
	if err != nil {
		t.Fatal(err)
	}
	private = append([]byte(nil), private...)
	private[31] ^= 1
	model := syntheticLegacyModel()
	mutatedSINF := append([]byte(nil), fixture.sinf...)
	privAtom, atomErr := uniqueAtom(fields, "priv")
	if atomErr != nil {
		t.Fatal(atomErr)
	}
	copy(mutatedSINF[privAtom.start:privAtom.end], private)
	_, err = currentSINFPrivateKey(model, mutatedSINF, fields)
	if !errors.Is(err, errCurrentSINFProfileMismatch) {
		t.Fatalf("mutated current SINF returned %v", err)
	}
}

func TestMissingPrivateModelDiagnostics(t *testing.T) {
	fixture := syntheticCurrentSINFFixture(t, 0x90a0b0c0, 7, 96, [16]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99})
	fields, err := parseSINFFields(fixture.sinf)
	if err != nil {
		t.Fatal(err)
	}
	private, err := sinfPrivatePayload(fixture.sinf, fields)
	if err != nil {
		t.Fatal(err)
	}
	private[31] ^= 1
	_, err = ResolveLogicalKey(fixture.sinf)
	if err == nil || !strings.Contains(err.Error(), "requires a private enrollment model") {
		t.Fatalf("missing-model error is unclear: %v", err)
	}
	for _, detail := range []string{
		fixture.selector.Identifier(),
		"sinf_sha256=" + digest(fixture.sinf),
		"priv_bytes=" + fmt.Sprint(len(private)),
		"priv_sha256=" + digest(private),
	} {
		if !strings.Contains(err.Error(), detail) {
			t.Fatalf("missing-model error omitted %q: %v", detail, err)
		}
	}
	if strings.Contains(err.Error(), "plaintext atom") {
		t.Fatalf("selector preflight attempted SINF model decoding: %v", err)
	}
}
