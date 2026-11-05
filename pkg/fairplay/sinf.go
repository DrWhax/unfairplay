package fairplay

import (
	"encoding/binary"
	"fmt"
)

type sinfAtom struct {
	typ   string
	start int
	end   int
}

type SINFSelector struct {
	User uint32 `json:"user"`
	Key  uint32 `json:"key"`
}

func (s SINFSelector) Identifier() string {
	return fmt.Sprintf("%08x:%08x", s.User, s.Key)
}

func sinfAtoms(blob []byte, start, end int) ([]sinfAtom, error) {
	var result []sinfAtom
	for cursor := start; cursor < end; {
		if end-cursor < 8 {
			return nil, fmt.Errorf("SINF atom list has a truncated header")
		}
		size := int(binary.BigEndian.Uint32(blob[cursor : cursor+4]))
		if size < 8 || size > end-cursor {
			return nil, fmt.Errorf("SINF atom has invalid bounds")
		}
		result = append(result, sinfAtom{
			typ: string(blob[cursor+4 : cursor+8]), start: cursor + 8, end: cursor + size,
		})
		cursor += size
	}
	return result, nil
}

func uniqueAtom(atoms []sinfAtom, typ string) (sinfAtom, error) {
	var found sinfAtom
	count := 0
	for _, atom := range atoms {
		if atom.typ == typ {
			found = atom
			count++
		}
	}
	if count != 1 {
		return sinfAtom{}, fmt.Errorf("SINF requires one %q atom, found %d", typ, count)
	}
	return found, nil
}

func sinfSelector(blob []byte, fields []sinfAtom) (SINFSelector, error) {
	user, err := uniqueAtom(fields, "user")
	if err != nil {
		return SINFSelector{}, err
	}
	key, err := uniqueAtom(fields, "key ")
	if err != nil {
		return SINFSelector{}, err
	}
	if user.end-user.start != 4 || key.end-key.start != 4 {
		return SINFSelector{}, fmt.Errorf("SINF user/key atom has invalid geometry")
	}
	return SINFSelector{
		User: binary.BigEndian.Uint32(blob[user.start:user.end]),
		Key:  binary.BigEndian.Uint32(blob[key.start:key.end]),
	}, nil
}

// ParseSINFSelector returns the personalized user/key selector carried by a
// SINF. It does not decrypt or otherwise interpret the private payload.
func ParseSINFSelector(blob []byte) (SINFSelector, error) {
	fields, err := parseSINFFields(blob)
	if err != nil {
		return SINFSelector{}, err
	}

	return sinfSelector(blob, fields)
}

func parseSINFFields(blob []byte) ([]sinfAtom, error) {
	roots, err := sinfAtoms(blob, 0, len(blob))
	if err != nil {
		return nil, err
	}
	if len(roots) != 1 || roots[0].typ != "sinf" || roots[0].start != 8 || roots[0].end != len(blob) {
		return nil, fmt.Errorf("SINF must contain one complete root atom")
	}
	children, err := sinfAtoms(blob, roots[0].start, roots[0].end)
	if err != nil {
		return nil, err
	}
	schi, err := uniqueAtom(children, "schi")
	if err != nil {
		return nil, err
	}
	return sinfAtoms(blob, schi.start, schi.end)
}

func sinfPrivatePayload(blob []byte, fields []sinfAtom) ([]byte, error) {
	priv, err := uniqueAtom(fields, "priv")
	if err != nil {
		return nil, err
	}
	if priv.start < 0 || priv.end < priv.start || priv.end > len(blob) {
		return nil, fmt.Errorf("SINF priv atom has invalid bounds")
	}
	return blob[priv.start:priv.end], nil
}
