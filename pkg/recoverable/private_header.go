package recoverable

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"errors"
)

var privateRecordHeader = [16]byte{'i', 't', 'u', 'n', 0, 0, 0, 12, 'v', 'e', 'r', 's', 0, 0, 0, 1}

// privateRecordIV binds the first encrypted record block to the visible fields.
// MD5 is required by this legacy format, not used as a general security hash.
func privateRecordIV(blob []byte, fm map[string]atom) ([16]byte, error) {
	var zero [16]byte
	name, nok := fm["name"]
	iv, iok := fm["iviv"]
	if !nok || !iok || name.start < 0 || name.end > len(blob) || name.end-name.start != 256 || iv.start < 0 || iv.end > len(blob) || iv.end-iv.start != 16 {
		return zero, errors.New("invalid private record IV fields")
	}
	n := blob[name.start:name.end]
	if end := bytes.IndexByte(n, 0); end >= 0 {
		n = n[:end]
	}
	data := append(bytes.Clone(n), blob[iv.start:iv.end]...)
	defer clear(data)
	return md5.Sum(data), nil
}

// validatePrivateRecordHeader checks the block which a body-only CBC decoder
// uses as its IV. Successful body decryption alone does not validate this header.
func validatePrivateRecordHeader(blob, p []byte, fm map[string]atom) error {
	iv, e := privateRecordIV(blob, fm)
	if e != nil {
		return e
	}
	a, ok := fm["priv"]
	if !ok || a.start < 0 || a.end > len(blob) || a.end-a.start < 16 || len(p) != 4184 {
		return errors.New("invalid private record header geometry")
	}
	raw := make([]byte, 16)
	defer clear(raw)
	for i, v := range blob[a.start : a.start+16] {
		raw[i] = p[88+i*256+int(v^p[72+i])]
	}
	block, e := aes.NewCipher(p[56:72])
	if e != nil {
		return e
	}
	cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(raw, raw)
	if !bytes.Equal(raw, privateRecordHeader[:]) {
		return errors.New("private record has invalid itun/vers header")
	}
	return nil
}
