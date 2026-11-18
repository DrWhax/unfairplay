package recoverable

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"testing"

	f "github.com/DrWhax/unfairplay/pkg/fairplay"
)

func TestGeneratedSINFContainsFullPrivateHeader(t *testing.T) {
	for _, tail := range []int{8, 16} {
		p := syntheticModel()
		for i := 0; i < 16; i++ {
			p[56+i] = byte(i + 11)
			p[72+i] = byte(i * 3)
			for j := 0; j < 256; j++ {
				p[88+i*256+j] = byte(j + 17 + i)
			}
		}
		b, e := newSINF(p, syntheticMetadata(8192, tail))
		if e != nil {
			t.Fatal(e)
		}
		fm, e := fields(b)
		if e != nil {
			t.Fatal(e)
		}
		priv := b[fm["priv"].start:fm["priv"].end]
		n := len(priv) / 16 * 16
		raw := make([]byte, n)
		for i, v := range priv[:n] {
			raw[i] = p[88+(i%16)*256+int(v^p[72+i%16])]
		}
		name := b[fm["name"].start:fm["name"].end]
		name = bytes.SplitN(name, []byte{0}, 2)[0]
		iv := md5.Sum(append(bytes.Clone(name), b[fm["iviv"].start:fm["iviv"].end]...))
		block, _ := aes.NewCipher(p[56:72])
		cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(raw, raw)
		expected := []byte{'i', 't', 'u', 'n', 0, 0, 0, 12, 'v', 'e', 'r', 's', 0, 0, 0, 1}
		if !bytes.Equal(raw[:16], expected) {
			t.Fatal("invalid full-record header")
		}
		if !bytes.Equal(raw[24:40], syntheticMetadata(8192, tail).ContentKey) {
			t.Fatal("content key changed")
		}
		if _, e = extractMetadata(b, p); e != nil {
			t.Fatal(e)
		}
	}
}

// The old encoder could pass key/body verification despite a broken first
// block. Changing visible IV or name recreates this failure without private data.
func TestBodyOnlySuccessDoesNotAcceptInvalidHeader(t *testing.T) {
	for _, field := range []string{"iviv", "name"} {
		p := syntheticModel()
		b, e := newSINF(p, syntheticMetadata(0, 16))
		if e != nil {
			t.Fatal(e)
		}
		fm, e := fields(b)
		if e != nil {
			t.Fatal(e)
		}
		b[fm[field].start] ^= 1
		key, e := f.ResolveLogicalKeyWithModel(b, p)
		if e != nil {
			t.Fatal("control must still pass body-only decoding", e)
		}
		clear(key.LogicalKey[:])
		if e = validatePrivateRecordHeader(b, p, fm); e == nil {
			t.Fatal("invalid header accepted")
		}
		if _, e = extractMetadata(b, p); e == nil {
			t.Fatal("source with invalid header accepted")
		}
	}
}
func TestPrivateRecordIVRejectsMalformedFields(t *testing.T) {
	p := syntheticModel()
	b, e := newSINF(p, syntheticMetadata(0, 16))
	if e != nil {
		t.Fatal(e)
	}
	fm, e := fields(b)
	if e != nil {
		t.Fatal(e)
	}
	a := fm["iviv"]
	a.end--
	fm["iviv"] = a
	if _, e = privateRecordIV(b, fm); e == nil {
		t.Fatal("short IV accepted")
	}
	delete(fm, "name")
	if _, e = privateRecordIV(b, fm); e == nil {
		t.Fatal("missing name accepted")
	}
}
