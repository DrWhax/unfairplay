package recovery

import (
	"bytes"
	"testing"

	"github.com/DrWhax/unfairplay/pkg/fairplay"
)

func TestRecoverySINFSelectorRejectsMalformedAndDuplicateAtoms(t *testing.T) {
	user := syntheticSINFAtom("user", []byte{1, 2, 3, 4})
	key := syntheticSINFAtom("key ", []byte{0xff, 0xff, 0xff, 0xff})
	priv := syntheticSINFAtom("priv", []byte{9, 8, 7})
	fieldList := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	wrap := func(fields []byte) []byte { return syntheticSINFAtom("sinf", syntheticSINFAtom("schi", fields)) }
	valid := fieldList(user, key, priv)
	tests := []struct {
		name                 string
		blob                 []byte
		publicOK, recoveryOK bool
	}{
		{"valid full uint32 key", wrap(valid), true, true},
		{"unknown fields", wrap(fieldList(syntheticSINFAtom("abcd", nil), valid)), true, true},
		{"duplicate user after valid fields", wrap(fieldList(valid, user)), false, false},
		{"duplicate key after valid fields", wrap(fieldList(valid, key)), false, false},
		{"malformed later field", wrap(fieldList(valid, []byte{0, 0, 0, 20, 'b', 'a', 'd', '!'})), false, false},
		{"truncated later field", wrap(fieldList(valid, []byte{0, 0, 0})), false, false},
		{"malformed later root child", syntheticSINFAtom("sinf", fieldList(syntheticSINFAtom("schi", valid), []byte{0, 0, 0})), false, false},
		{"duplicate schi", syntheticSINFAtom("sinf", fieldList(syntheticSINFAtom("schi", valid), syntheticSINFAtom("schi", valid))), false, false},
		{"extra root", fieldList(wrap(valid), syntheticSINFAtom("junk", nil)), false, false},
		{"invalid selector geometry", wrap(fieldList(syntheticSINFAtom("user", []byte{1}), key, priv)), false, false},
		{"missing private", wrap(fieldList(user, key)), true, false},
		{"duplicate private", wrap(fieldList(valid, priv)), true, false},
		{"private outside schi", syntheticSINFAtom("sinf", fieldList(syntheticSINFAtom("schi", fieldList(user, key)), priv)), true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			public, publicErr := fairplay.ParseSINFSelector(tc.blob)
			parsed, err := parseRecoverySINF(tc.blob)
			if (publicErr == nil) != tc.publicOK || (err == nil) != tc.recoveryOK {
				t.Fatalf("public error %v, recovery error %v", publicErr, err)
			}
			_, _, selectorErr := enrollmentSINFSelector(tc.blob)
			_, privateErr := currentSINFPrivateSource(tc.blob)
			if (selectorErr == nil) != tc.recoveryOK || (privateErr == nil) != tc.recoveryOK {
				t.Fatalf("selector error %v, private error %v", selectorErr, privateErr)
			}
			if tc.recoveryOK && (parsed.selector != public || !bytes.Equal(parsed.private, []byte{9, 8, 7})) {
				t.Fatalf("selector or bound payload differs: %+v", parsed)
			}
		})
	}
}

func TestRecoverySINFSelectorPreservesPrivateGeometry(t *testing.T) {
	for _, rights := range []int{88, 104} {
		sinf := syntheticCurrentSINFForPrecursorRights(t, [16]byte{}, rights)
		parsed, err := parseRecoverySINF(sinf)
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, err = currentSINFLogicalSource(sinf)
		if err != nil {
			t.Fatalf("rights size %d: %v", rights, err)
		}
		if len(parsed.private) == 0 {
			t.Fatal("empty private payload")
		}
	}
}
