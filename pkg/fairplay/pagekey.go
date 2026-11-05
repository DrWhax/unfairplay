package fairplay

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

var fixedPageAESKey = [16]byte{0xf5, 0x88, 0xff, 0xe1, 0x89, 0xf9, 0x89, 0xf8, 0xe1, 0xf8, 0x89, 0xfe, 0x8a, 0xe1, 0xf4, 0xfe}

var (
	pageFoldPermutation = [...][8]int{{0, 1, 2, 3, 4, 5, 6, 7}, {2, 1, 0, 3, 4, 7, 6, 5}, {2, 0, 4, 1, 6, 3, 7, 5}, {1, 2, 4, 0, 7, 3, 5, 6}}
	pageFoldPairXOR     = [...]uint32{0x68547c2e, 0x7e05e1de, 0xd495038b, 0x0ab24add}
	pageFoldOutputXOR   = [...]uint32{0x5b7198c7, 0xeb5de22c, 0x0f8aa8fa, 0xf6e1bb3f}
)

// appMaskFromLogicalKey reverses logicalFromInnerKey's word encoding. The
// former MixColumns/InvMixColumns pair cancels, and the packed-byte additions
// cancel the final addend. newPageKeyDeriver cancels the remaining whitening,
// so the page AES cipher uses the original inner key.
func appMaskFromLogicalKey(logical [16]byte) (mask [16]byte) {
	for word := 0; word < 4; word++ {
		inner := binary.LittleEndian.Uint32(logical[word*4:]) - uint32(word+13)*0xa6b13d89
		whitening := binary.BigEndian.Uint32(fixedPageAESKey[word*4:])
		binary.BigEndian.PutUint32(mask[word*4:], inner^whitening)
	}
	return
}

// pageFold keeps decoded halfwords throughout. The former Boolean gates
// are word packing, and only the low half of the final 64-bit expression is
// consumed: that half is the XOR fold of the square's high and low words.
func pageFold(input [16]byte) [16]byte {
	var initial, state [8]uint16
	for i := range initial {
		initial[i] = binary.BigEndian.Uint16(input[i*2:])
		state[i] = initial[i]
	}
	for _, permutation := range pageFoldPermutation {
		var next [8]uint16
		for pair := 0; pair < 4; pair++ {
			sum := uint32(state[permutation[pair*2]]) + uint32(state[permutation[pair*2+1]])
			// The sum of two halfwords has a one-bit carry, whose square is itself.
			square := sum*sum ^ pageFoldPairXOR[pair] ^ (sum >> 16)
			next[pair*2], next[pair*2+1] = uint16(square), uint16(square>>16)
		}
		state = next
	}
	pack := func(high, low int) uint32 { return uint32(state[high])<<16 | uint32(state[low]) }
	combined := [4]uint32{
		pack(3, 2) + pack(1, 0),
		pack(6, 4) + pack(2, 0),
		pack(7, 5) + pack(3, 0),
		pack(7, 6) + pack(5, 4),
	}
	var output [16]byte
	for pair, value := range combined {
		square := uint64(value) * uint64(value)
		folded := uint32(square) ^ uint32(square>>32) ^ pageFoldOutputXOR[pair]
		binary.BigEndian.PutUint16(output[pair*4:], initial[pair*2]^uint16(folded))
		binary.BigEndian.PutUint16(output[pair*4+2:], initial[pair*2+1]^uint16(folded>>16))
	}
	return output
}

type pageKeyDeriver struct {
	block cipher.Block
}

func newPageKeyDeriver(appMask [16]byte) *pageKeyDeriver {
	var effective [16]byte
	for i := range effective {
		effective[i] = fixedPageAESKey[i] ^ appMask[i]
	}
	block, _ := aes.NewCipher(effective[:])
	clear(effective[:])
	return &pageKeyDeriver{block: block}
}

func (deriver *pageKeyDeriver) pageKey(wrapped []byte, cryptOffset uint64) [16]byte {
	var padding [8]byte
	binary.BigEndian.PutUint64(padding[:], cryptOffset)
	return deriver.pageKeyWithPadding(wrapped, padding)
}

func (deriver *pageKeyDeriver) pageKeyWithPadding(wrapped []byte, padding [8]byte) [16]byte {
	var plaintext [3][16]byte
	copy(plaintext[0][:8], wrapped[8:])
	copy(plaintext[0][8:], padding[:])
	copy(plaintext[1][:], wrapped)
	copy(plaintext[2][:8], padding[:])
	copy(plaintext[2][8:], wrapped[:8])
	var encrypted [3][16]byte
	for i := range encrypted {
		deriver.block.Encrypt(encrypted[i][:], plaintext[i][:])
	}
	state := pageFold(encrypted[0])
	for i := range state {
		state[i] ^= encrypted[1][i]
	}
	state = pageFold(state)
	for i := range state {
		state[i] ^= encrypted[2][i]
	}
	return pageFold(state)
}
