package recoverable

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"

	f "github.com/DrWhax/unfairplay/pkg/fairplay"
)

// extractMetadata validates the supported atom layout before retaining only
// explicitly selected source fields. It never stores an original SINF blob.
func extractMetadata(b, p []byte) (applicationMetadata, error) {
	var m applicationMetadata
	if len(b) > 4096 {
		return m, errors.New("oversized source SINF")
	}
	key, e := f.ResolveLogicalKeyWithModel(b, p)
	if e != nil {
		return m, e
	}
	defer clear(key.LogicalKey[:])
	fm, e := fields(b)
	if e != nil {
		return m, e
	}
	if e = validatePrivateRecordHeader(b, p, fm); e != nil {
		return m, e
	}
	outer, e := atoms(b, 8, len(b))
	if e != nil {
		return m, e
	}
	if len(outer) != 4 {
		return m, errors.New("unsupported source SINF fields")
	}
	for i, k := range []string{"frma", "schm", "schi", "sign"} {
		if outer[i].name != k {
			return m, errors.New("unsupported source SINF ordering")
		}
	}
	if outer[3].end-outer[3].start != 128 {
		return m, errors.New("unsupported signature extent")
	}
	if e = validateSourceScheme(fm); e != nil {
		return m, e
	}
	return extractKnownSource(b, p, key.LogicalKey, fm, outer)
}

func validateSourceScheme(fm map[string]atom) error {
	for k, size := range map[string]int{"user": 4, "key ": 4, "iviv": 16, "name": 256} {
		a, ok := fm[k]
		if !ok || a.end-a.start != size {
			return errors.New("unsupported source scheme field geometry")
		}
	}
	for name, a := range fm {
		switch name {
		case "user", "key ", "iviv", "righ", "name", "priv":
		case "crdt", "asdt":
			// Known optional fields in the macOS SINF layout. They do not
			// contribute to the account-neutral recovery record.
			if a.end-a.start != 4 {
				return errors.New("invalid optional source scheme field geometry")
			}
		default:
			return errors.New("unknown source scheme field")
		}
	}
	return nil
}

func extractKnownSource(b, p []byte, logical [16]byte, fm map[string]atom, outer []atom) (applicationMetadata, error) {
	var m applicationMetadata
	ra, ok := fm["righ"]
	if !ok {
		return m, errors.New("missing source rights")
	}
	m, e := sourceMetadata(b[ra.start:ra.end])
	if e != nil {
		return m, e
	}
	priv := fm["priv"]
	v := b[priv.start:priv.end]
	if len(v) < 32 {
		return m, errors.New("truncated private envelope")
	}
	n := (len(v) - 16) / 16 * 16
	tail := len(v) - 16 - n
	if tail != 0 && tail != 8 {
		return m, errors.New("unsupported private trailer")
	}
	for _, x := range v[16+n:] {
		if x != 0 {
			return m, errors.New("nonzero private padding")
		}
	}
	raw := make([]byte, 16+n)
	defer clear(raw)
	for i := range raw {
		raw[i] = p[88+(i%16)*256+int(v[i]^p[72+i%16])]
	}
	block, e := aes.NewCipher(p[56:72])
	if e != nil {
		return m, e
	}
	plain := make([]byte, n)
	defer func() { clear(plain) }()
	cipher.NewCBCDecrypter(block, raw[:16]).CryptBlocks(plain, raw[16:])
	plain = append(plain, v[16+n:]...)
	aa, e := atoms(plain, 0, len(plain))
	if e != nil {
		return m, e
	}
	if len(aa) != 5 {
		return m, errors.New("unsupported private fields")
	}
	for i, k := range []string{"key ", "iviv", "tmpr", "righ", "name"} {
		if aa[i].name != k {
			return m, errors.New("unsupported private field order")
		}
	}
	for _, i := range []int{0, 1, 2} {
		if aa[i].end-aa[i].start != 16 {
			return m, errors.New("unsupported private value geometry")
		}
	}
	if aa[4].end-aa[4].start != 256 || !bytes.Equal(plain[aa[3].start:aa[3].end], b[ra.start:ra.end]) {
		return m, errors.New("private and visible rights disagree")
	}
	appkey := plain[aa[0].start:aa[0].end]
	for i := 0; i < 4; i++ {
		if binary.BigEndian.Uint32(appkey[i*4:])+uint32(i+13)*0xa6b13d89 != binary.LittleEndian.Uint32(logical[i*4:]) {
			return m, errors.New("private content key mismatch")
		}
	}
	m.ContentKey = bytes.Clone(appkey)
	m.PrivateIV = bytes.Clone(plain[aa[1].start:aa[1].end])
	m.Format = bytes.Clone(b[outer[0].start:outer[0].end])
	m.Scheme = bytes.Clone(b[outer[1].start:outer[1].end])
	if e = m.validate(); e != nil {
		m.clearSecrets()
		return applicationMetadata{}, e
	}
	return m, nil
}
