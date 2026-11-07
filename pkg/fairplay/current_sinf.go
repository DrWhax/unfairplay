package fairplay

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	currentSINFModelV1Bytes  = 8 + 4 + 4 + 32 + 16 + 16 + 16*256
	currentSINFModelV2Bytes  = 8 + 4 + 4 + 32 + 4 + 4 + 16 + 16 + 16*256
	currentSINFV3SourceBytes = 27 * aes.BlockSize
	currentSINFModelV3Bytes  = 8 + 4 + 4 + 32 + 4 + 4 + 4 + 4 + 4 + 16 + 16*256 + currentSINFV3SourceBytes + 16*256
	legacySINFModelMagic     = "FPS26A4\x00"
	enrollmentModelV1Magic   = "FPSENR1\x00"
	enrollmentModelV2Magic   = "FPSENR2\x00"
	enrollmentModelV3Magic   = "FPSENR3\x00"
)

var errCurrentSINFProfileMismatch = errors.New("SINF does not match the selected FairPlay model")

type currentSINFModel struct {
	version       uint32
	modelIdentity [32]byte
	selector      SINFSelector
	hasSelector   bool
	key           [16]byte
	whitening     [16]byte
	inputDecode   [16 * 256]byte
	sourceOffset  int32
	sourceBytes   uint32
	finalXOR      byte
	outputEncode  [16 * 256]byte
	outputMask    [currentSINFV3SourceBytes]byte
	postDecode    [16 * 256]byte
}

func parseCurrentSINFModel(pack []byte) (currentSINFModel, error) {
	var model currentSINFModel
	if len(pack) < 16 || binary.LittleEndian.Uint32(pack[12:16]) != uint32(len(pack)) {
		return model, fmt.Errorf("invalid current SINF model envelope")
	}
	var payloadOffset int
	switch {
	case len(pack) == currentSINFModelV1Bytes &&
		(string(pack[:8]) == legacySINFModelMagic || string(pack[:8]) == enrollmentModelV1Magic) &&
		binary.LittleEndian.Uint32(pack[8:12]) == 1:
		model.version = 1
		copy(model.modelIdentity[:], pack[16:48])
		payloadOffset = 48
	case len(pack) == currentSINFModelV2Bytes &&
		string(pack[:8]) == enrollmentModelV2Magic &&
		binary.LittleEndian.Uint32(pack[8:12]) == 2:
		model.version = 2
		copy(model.modelIdentity[:], pack[16:48])
		model.selector = SINFSelector{
			User: binary.LittleEndian.Uint32(pack[48:52]),
			Key:  binary.LittleEndian.Uint32(pack[52:56]),
		}
		model.hasSelector = true
		payloadOffset = 56
	case len(pack) == currentSINFModelV3Bytes &&
		string(pack[:8]) == enrollmentModelV3Magic &&
		binary.LittleEndian.Uint32(pack[8:12]) == 3:
		model.version = 3
		copy(model.modelIdentity[:], pack[16:48])
		model.selector = SINFSelector{
			User: binary.LittleEndian.Uint32(pack[48:52]),
			Key:  binary.LittleEndian.Uint32(pack[52:56]),
		}
		model.hasSelector = true
		model.sourceOffset = int32(binary.LittleEndian.Uint32(pack[56:60]))
		model.sourceBytes = binary.LittleEndian.Uint32(pack[60:64])
		model.finalXOR = pack[64]
		if pack[65] != 0 || pack[66] != 0 || pack[67] != 0 ||
			model.sourceOffset < 0 || model.sourceBytes != currentSINFV3SourceBytes {
			return currentSINFModel{}, fmt.Errorf("invalid current SINF version 3 geometry")
		}
		payloadOffset = 68
	default:
		return model, fmt.Errorf("invalid current SINF model envelope")
	}
	copy(model.key[:], pack[payloadOffset:payloadOffset+16])
	if model.version < 3 {
		copy(model.whitening[:], pack[payloadOffset+16:payloadOffset+32])
		copy(model.inputDecode[:], pack[payloadOffset+32:])
	} else {
		cursor := payloadOffset + 16
		copy(model.outputEncode[:], pack[cursor:cursor+len(model.outputEncode)])
		cursor += len(model.outputEncode)
		copy(model.outputMask[:], pack[cursor:cursor+len(model.outputMask)])
		cursor += len(model.outputMask)
		copy(model.postDecode[:], pack[cursor:cursor+len(model.postDecode)])
	}
	if model.version < 3 {
		if err := validateBytePermutations("input", model.inputDecode[:]); err != nil {
			return currentSINFModel{}, err
		}
	} else {
		if err := validateBytePermutations("output", model.outputEncode[:]); err != nil {
			return currentSINFModel{}, err
		}
		if err := validateBytePermutations("post-codec", model.postDecode[:]); err != nil {
			return currentSINFModel{}, err
		}
	}
	return model, nil
}

func validateBytePermutations(kind string, tables []byte) error {
	if len(tables) == 0 || len(tables)%256 != 0 {
		return fmt.Errorf("current SINF %s tables have invalid size", kind)
	}
	for position := 0; position < len(tables)/256; position++ {
		var seen [256]bool
		for _, value := range tables[position*256 : (position+1)*256] {
			if seen[value] {
				return fmt.Errorf("current SINF %s table %d is not a permutation", kind, position)
			}
			seen[value] = true
		}
	}
	return nil
}

func currentSINFPrivateKey(model currentSINFModel, sinf []byte, fields []sinfAtom) ([16]byte, error) {
	if model.version == 3 {
		return currentSINFPrivateKeyV3(model, sinf, fields)
	}
	source, err := sinfPrivatePayload(sinf, fields)
	if err != nil {
		return [16]byte{}, err
	}
	return currentSINFPrivateKeyLegacy(model, source)
}

func currentSINFPrivateKeyLegacy(model currentSINFModel, source []byte) ([16]byte, error) {
	var innerKey [16]byte
	plaintext, err := currentSINFPrivatePlaintextLegacy(model, source)
	if err != nil {
		return innerKey, err
	}
	defer clear(plaintext)
	copy(innerKey[:], plaintext[8:24])
	return innerKey, nil
}

func currentSINFPrivatePlaintextLegacy(model currentSINFModel, source []byte) ([]byte, error) {
	if len(source) < 48 {
		return nil, fmt.Errorf("%w: priv source is too short", errCurrentSINFProfileMismatch)
	}
	bodyBytes := len(source) - aes.BlockSize
	trailerBytes := bodyBytes % aes.BlockSize
	ciphertextBytes := bodyBytes - trailerBytes
	if ciphertextBytes < 2*aes.BlockSize || trailerBytes != 0 && trailerBytes != 8 {
		return nil, fmt.Errorf("%w: priv block geometry is invalid", errCurrentSINFProfileMismatch)
	}
	encodedBytes := aes.BlockSize + ciphertextBytes
	trailer := source[encodedBytes:]
	for _, value := range trailer {
		if value != 0 {
			return nil, fmt.Errorf("%w: priv trailer is not zero", errCurrentSINFProfileMismatch)
		}
	}

	logical := make([]byte, encodedBytes)
	defer clear(logical)
	for index, value := range source[:encodedBytes] {
		position := index % aes.BlockSize
		external := value ^ model.whitening[position]
		logical[index] = model.inputDecode[position*256+int(external)]
	}
	decrypted, err := aesCBCDecrypt(logical[aes.BlockSize:], model.key[:], logical[:aes.BlockSize])
	if err != nil {
		return nil, fmt.Errorf("decode selected current SINF model: %w", err)
	}
	defer clear(decrypted)
	plaintext := make([]byte, len(decrypted)+len(trailer))
	copy(plaintext, decrypted)
	copy(plaintext[len(decrypted):], trailer)
	if err := validateCurrentSINFPrivatePlaintext(plaintext); err != nil {
		clear(plaintext)
		return nil, err
	}
	return plaintext, nil
}

func validateCurrentSINFPrivatePlaintext(plaintext []byte) error {
	expectedAtoms := [...]struct {
		typ  string
		size int
	}{
		{"key ", 24},
		{"iviv", 24},
		{"tmpr", 24},
		{"righ", 0},
		{"name", 264},
	}
	cursor := 0
	for index, expected := range expectedAtoms {
		atom, parseErr := parseClearAtom(plaintext, cursor, len(plaintext))
		if parseErr != nil {
			return fmt.Errorf("%w: plaintext atom %d: %v", errCurrentSINFProfileMismatch, index, parseErr)
		}
		if atom.typ != expected.typ {
			return fmt.Errorf("%w: plaintext has invalid %s atom", errCurrentSINFProfileMismatch, expected.typ)
		}
		if atom.typ == "righ" {
			if rightsErr := currentSINFRightsPayloadGeometry(plaintext[cursor+8 : atom.end]); rightsErr != nil {
				return fmt.Errorf("%w: plaintext has invalid rights: %v", errCurrentSINFProfileMismatch, rightsErr)
			}
		} else if atom.end-cursor != expected.size {
			return fmt.Errorf("%w: plaintext has invalid %s atom", errCurrentSINFProfileMismatch, expected.typ)
		}
		cursor = atom.end
	}
	if cursor != len(plaintext) {
		return fmt.Errorf("%w: plaintext has trailing data", errCurrentSINFProfileMismatch)
	}
	return nil
}

func currentSINFPrivateKeyV3(model currentSINFModel, sinf []byte, fields []sinfAtom) ([16]byte, error) {
	var innerKey [16]byte
	private, err := uniqueAtom(fields, "priv")
	if err != nil {
		return innerKey, err
	}
	start64 := int64(model.sourceOffset)
	end64 := start64 + int64(model.sourceBytes)
	if start64 < int64(private.start) || start64 > int64(private.end) ||
		end64 < start64 || end64 > int64(len(sinf)) {
		return innerKey, fmt.Errorf("%w: version 3 source has invalid bounds", errCurrentSINFProfileMismatch)
	}
	source := sinf[int(start64):int(end64)]
	if len(source) != currentSINFV3SourceBytes {
		return innerKey, fmt.Errorf("%w: version 3 source has invalid geometry", errCurrentSINFProfileMismatch)
	}

	block, err := aes.NewCipher(model.key[:])
	if err != nil {
		return innerKey, fmt.Errorf("decode current SINF version 3 model: %w", err)
	}
	internal := make([]byte, len(source))
	plaintext := make([]byte, len(source))
	defer func() {
		clear(internal)
		clear(plaintext)
	}()
	for offset := 0; offset < len(source); offset += aes.BlockSize {
		block.Decrypt(internal[offset:offset+aes.BlockSize], source[offset:offset+aes.BlockSize])
	}
	for index, value := range internal {
		position := index % aes.BlockSize
		external := model.outputEncode[position*256+int(value)] ^ model.outputMask[index]
		plaintext[index] = model.postDecode[position*256+int(external)] ^ model.finalXOR
	}

	if err := validateCurrentSINFV3Plaintext(plaintext); err != nil {
		return innerKey, fmt.Errorf("%w: %v", errCurrentSINFProfileMismatch, err)
	}
	copy(innerKey[:], plaintext[24:40])
	return innerKey, nil
}

func validateCurrentSINFV3Plaintext(plaintext []byte) error {
	if len(plaintext) != currentSINFV3SourceBytes {
		return fmt.Errorf("version 3 plaintext has invalid size")
	}
	if string(plaintext[0:4]) != "itun" || binary.BigEndian.Uint32(plaintext[4:8]) != 12 ||
		string(plaintext[8:12]) != "vers" || binary.BigEndian.Uint32(plaintext[12:16]) != 1 {
		return fmt.Errorf("version 3 plaintext has invalid header")
	}
	expected := [...]struct {
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
	for _, field := range expected {
		if binary.BigEndian.Uint32(plaintext[field.offset:field.offset+4]) != field.size ||
			string(plaintext[field.offset+4:field.offset+8]) != field.typ {
			return fmt.Errorf("version 3 plaintext has invalid %s field", field.typ)
		}
	}
	// The native 432-byte work buffer deliberately carries only the first 256
	// bytes of the final 264-byte name record. The remaining eight bytes are
	// outside this protected frame, so accepting any other truncation would be
	// a model mismatch.
	if 176+int(binary.BigEndian.Uint32(plaintext[176:180])) != len(plaintext)+8 {
		return fmt.Errorf("version 3 plaintext has invalid name geometry")
	}
	return nil
}
