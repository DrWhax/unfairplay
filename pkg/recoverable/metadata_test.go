package recoverable

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"testing"
)

func syntheticMetadata(mode uint32, tail int) applicationMetadata {
	m := applicationMetadata{Schema: metadataSchema, Rights: applicationRights{1, 2, 3, 4, 5, 6, 128, mode}, ContentKey: bytes.Repeat([]byte{0x42}, 16), PrivateIV: bytes.Repeat([]byte{0x71}, 16), Format: []byte("game"), Scheme: []byte{0, 0, 0, 0, 'i', 't', 'u', 'n', 0, 0, 0, 0}, RightsTail: bytes.Repeat([]byte{0x37}, tail)}
	return m
}
func syntheticModel() []byte {
	p := make([]byte, 4184)
	copy(p, "FPSENR2\x00")
	binary.LittleEndian.PutUint32(p[8:], 2)
	binary.LittleEndian.PutUint32(p[12:], uint32(len(p)))
	binary.LittleEndian.PutUint32(p[48:], 123)
	binary.LittleEndian.PutUint32(p[52:], 7)
	for i := 0; i < 16; i++ {
		for j := 0; j < 256; j++ {
			p[88+i*256+j] = byte(j)
		}
	}
	return p
}
func TestSourceSharedFieldsRoundTrip(t *testing.T) {
	for _, mode := range []uint32{0, 8192, 1234} {
		for _, tail := range []int{8, 16} {
			m := syntheticMetadata(mode, tail)
			p := syntheticModel()
			sinf, e := newSINF(p, m)
			if e != nil {
				t.Fatal(e)
			}
			extracted, e := extractMetadata(sinf, p)
			if e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(extracted, m) {
				t.Fatal("shared source fields changed")
			}
			b, e := json.Marshal(extracted)
			if e != nil {
				t.Fatal(e)
			}
			decoded, e := decodeMetadata(b)
			if e != nil || !reflect.DeepEqual(decoded, m) {
				t.Fatal("capsule roundtrip", e)
			}
			r := decoded.bytes()
			if len(r) != 72+tail || !bytes.Equal(r[72:], m.RightsTail) || binary.BigEndian.Uint32(r[68:72]) != mode || binary.BigEndian.Uint32(r[28:32]) != 0 {
				t.Fatal("source policy changed")
			}
			// Source transaction is explicitly dropped while the opaque trailer stays.
			binary.BigEndian.PutUint32(r[28:32], 0xabcdef01)
			policy, e := sourceMetadata(r)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(policy.bytes()[72:], m.RightsTail) || binary.BigEndian.Uint32(policy.bytes()[28:32]) != 0 {
				t.Fatal("transaction retained or trailer changed")
			}
		}
	}
}
func TestRecoveryMetadataRejectsAmbiguity(t *testing.T) {
	m := syntheticMetadata(0, 16)
	b, _ := json.Marshal(m)
	for _, bad := range [][]byte{[]byte(`{}`), append(bytes.Clone(b), []byte(`{}`)...), bytes.Replace(b, []byte(`"schema":`), []byte(`"account":"secret","schema":`), 1), bytes.Replace(b, []byte(`"mode":0`), []byte(`"mode":0,"mode":8192`), 1), bytes.Replace(b, []byte(metadataSchema), []byte("unknown"), 1), bytes.Replace(b, []byte(`"mode":0`), []byte(`"mode":null`), 1)} {
		if _, e := decodeMetadata(bad); e == nil {
			t.Fatal("invalid metadata accepted")
		}
	}
	for _, mutate := range []func(*applicationMetadata){func(m *applicationMetadata) { m.ContentKey = m.ContentKey[:15] }, func(m *applicationMetadata) { m.PrivateIV = nil }, func(m *applicationMetadata) { m.RightsTail = []byte{1} }, func(m *applicationMetadata) { m.Format = []byte("other") }, func(m *applicationMetadata) { m.Scheme[0] = 1 }} {
		x := syntheticMetadata(0, 16)
		mutate(&x)
		bad, _ := json.Marshal(x)
		if _, e := decodeMetadata(bad); e == nil {
			t.Fatal("invalid field geometry accepted")
		}
	}
}
func TestSourceRejectsVisiblePrivateRightsMismatch(t *testing.T) {
	p := syntheticModel()
	b, e := newSINF(p, syntheticMetadata(0, 16))
	if e != nil {
		t.Fatal(e)
	}
	fm, e := fields(b)
	if e != nil {
		t.Fatal(e)
	}
	b[fm["righ"].start+71] ^= 1
	if _, e := extractMetadata(b, p); e == nil {
		t.Fatal("disagreeing source rights accepted")
	}
}

func TestSourceOptionalSchemeFields(t *testing.T) {
	p := syntheticModel()
	want := syntheticMetadata(0, 8)
	original, err := newSINF(p, want)
	if err != nil {
		t.Fatal(err)
	}
	schi, err := field(original, 8, len(original), "schi")
	if err != nil {
		t.Fatal(err)
	}
	crdt := makeAtom("crdt", []byte{1, 2, 3, 4})
	asdt := makeAtom("asdt", []byte{5, 6, 7, 8})
	for _, tc := range []struct {
		name   string
		extra  []byte
		reject bool
	}{
		{"crdt only", crdt, false},
		{"asdt only", asdt, false},
		{"both", append(bytes.Clone(crdt), asdt...), false},
		{"invalid size", makeAtom("crdt", []byte{1}), true},
		{"unknown field", makeAtom("test", []byte{1, 2, 3, 4}), true},
		{"duplicate field", append(bytes.Clone(asdt), asdt...), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := append(bytes.Clone(original[schi.start:schi.end]), tc.extra...)
			outer := append(bytes.Clone(original[8:schi.start-8]), makeAtom("schi", body)...)
			outer = append(outer, original[schi.end:]...)
			got, err := extractMetadata(makeAtom("sinf", outer), p)
			if tc.reject {
				if err == nil {
					t.Fatal("invalid scheme accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatal("optional fields changed recovery metadata")
			}
		})
	}
}
