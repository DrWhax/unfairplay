package fairplay

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

type clearAtom struct {
	typ         string
	offset, end int
}

func parseClearAtom(blob []byte, offset, limit int) (clearAtom, error) {
	if offset < 0 || limit > len(blob) || limit-offset < 8 {
		return clearAtom{}, fmt.Errorf("atom is truncated")
	}
	size := int(binary.BigEndian.Uint32(blob[offset : offset+4]))
	if size < 8 || size > limit-offset {
		return clearAtom{}, fmt.Errorf("atom has invalid bounds")
	}
	return clearAtom{typ: string(blob[offset+4 : offset+8]), offset: offset, end: offset + size}, nil
}

func aesCBCDecrypt(input, key, iv []byte) ([]byte, error) {
	if len(input)%aes.BlockSize != 0 || len(key) != aes.BlockSize || len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid AES-CBC geometry")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	output := make([]byte, len(input))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(output, input)
	return output, nil
}

func logicalFromInnerKey(innerKey [16]byte) [16]byte {
	var logical [16]byte
	for word := 0; word < 4; word++ {
		decoded := binary.BigEndian.Uint32(innerKey[word*4 : (word+1)*4])
		decoded += uint32(13+word) * 0xa6b13d89
		binary.LittleEndian.PutUint32(logical[word*4:(word+1)*4], decoded)
	}
	return logical
}
