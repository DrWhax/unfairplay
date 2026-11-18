package recoverable

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const recoverySuffix = ".sinf-recovery"
const metadataSchema = "unfairplay-sinf-recovery-v2"

// Known application fields and the opaque rights trailer are retained. Trailer
// equality was observed across private controls; universal semantics are not claimed.
type applicationRights struct {
	VeID uint32 `json:"veID"`
	Plat uint32 `json:"plat"`
	Aver uint32 `json:"aver"`
	Sing uint32 `json:"sing"`
	Song uint32 `json:"song"`
	Tool uint32 `json:"tool"`
	Medi uint32 `json:"medi"`
	Mode uint32 `json:"mode"`
}
type applicationMetadata struct {
	Schema     string            `json:"schema"`
	Rights     applicationRights `json:"rights"`
	RightsTail []byte            `json:"rights_tail"`
	ContentKey []byte            `json:"content_key"`
	PrivateIV  []byte            `json:"private_iv"`
	Format     []byte            `json:"format"`
	Scheme     []byte            `json:"scheme"`
}

func sourceMetadata(rights []byte) (applicationMetadata, error) {
	var m applicationMetadata
	if len(rights) != 80 && len(rights) != 88 {
		return m, errors.New("unsupported source rights extent")
	}
	for i, k := range []string{"veID", "plat", "aver", "tran", "sing", "song", "tool", "medi", "mode"} {
		if string(rights[i*8:i*8+4]) != k {
			return m, errors.New("unsupported source rights tags")
		}
	}
	// Preserve the observed opaque source trailer exactly, including its length.
	v := func(i int) uint32 { return binary.BigEndian.Uint32(rights[i : i+4]) }
	m = applicationMetadata{Schema: metadataSchema, Rights: applicationRights{v(4), v(12), v(20), v(36), v(44), v(52), v(60), v(68)}, RightsTail: bytes.Clone(rights[72:])}
	if m.Rights.Medi != 128 {
		return m, errors.New("unsupported media class")
	}
	return m, nil
}
func (m applicationMetadata) bytes() []byte {
	r := make([]byte, 72+len(m.RightsTail))
	copy(r[72:], m.RightsTail)
	values := []uint32{m.Rights.VeID, m.Rights.Plat, m.Rights.Aver, 0, m.Rights.Sing, m.Rights.Song, m.Rights.Tool, m.Rights.Medi, m.Rights.Mode}
	for i, k := range []string{"veID", "plat", "aver", "tran", "sing", "song", "tool", "medi", "mode"} {
		copy(r[i*8:], k)
		binary.BigEndian.PutUint32(r[i*8+4:], values[i])
	}
	return r
}
func decodeMetadata(b []byte) (applicationMetadata, error) {
	var m applicationMetadata
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(&m); e != nil {
		return m, e
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return m, errors.New("trailing recovery metadata")
	}
	// Canonical encoding rejects missing fields, duplicate fields, alternate names
	// and ambiguous values instead of silently inventing missing source policy.
	canonical, e := json.Marshal(m)
	if e != nil {
		return m, e
	}
	if !bytes.Equal(b, canonical) {
		return m, errors.New("noncanonical or incomplete recovery metadata")
	}
	if err := m.validate(); err != nil {
		return m, err
	}
	if m.Schema != metadataSchema || m.Rights.Medi != 128 {
		return m, errors.New("unsupported recovery metadata schema or media class")
	}
	return m, nil
}

func (m applicationMetadata) validate() error {
	if m.Schema != metadataSchema || m.Rights.Medi != 128 || (len(m.RightsTail) != 8 && len(m.RightsTail) != 16) || len(m.ContentKey) != 16 || len(m.PrivateIV) != 16 || !bytes.Equal(m.Format, []byte("game")) || !bytes.Equal(m.Scheme, []byte{0, 0, 0, 0, 'i', 't', 'u', 'n', 0, 0, 0, 0}) {
		return errors.New("unsupported SINF recovery schema, field geometry or content profile")
	}
	return nil
}
func (m *applicationMetadata) clearSecrets() { clear(m.ContentKey); clear(m.PrivateIV) }
