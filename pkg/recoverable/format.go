package recoverable

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	f "github.com/DrWhax/unfairplay/pkg/fairplay"
	"howett.net/plist"
)

type atom struct {
	name       string
	start, end int
}

func atoms(b []byte, start, end int) ([]atom, error) {
	var out []atom
	seen := map[string]bool{}
	for start < end {
		if start < 0 || end > len(b) || end-start < 8 {
			return nil, errors.New("atom bounds")
		}
		n := int(binary.BigEndian.Uint32(b[start:]))
		if n < 8 || n > end-start {
			return nil, errors.New("atom length")
		}
		k := string(b[start+4 : start+8])
		if seen[k] {
			return nil, errors.New("duplicate atom")
		}
		seen[k] = true
		out = append(out, atom{k, start + 8, start + n})
		start += n
	}
	return out, nil
}
func field(b []byte, start, end int, name string) (atom, error) {
	a, e := atoms(b, start, end)
	if e != nil {
		return atom{}, e
	}
	for _, x := range a {
		if x.name == name {
			return x, nil
		}
	}
	return atom{}, errors.New("missing atom")
}
func fields(b []byte) (map[string]atom, error) {
	a, e := atoms(b, 0, len(b))
	if e != nil || len(a) != 1 || a[0].name != "sinf" {
		return nil, errors.New("SINF root")
	}
	s, e := field(b, 8, len(b), "schi")
	if e != nil {
		return nil, e
	}
	a, e = atoms(b, s.start, s.end)
	if e != nil {
		return nil, e
	}
	m := map[string]atom{}
	for _, v := range a {
		m[v.name] = v
	}
	for _, k := range []string{"user", "key ", "priv"} {
		if _, ok := m[k]; !ok {
			return nil, errors.New("SINF field missing")
		}
	}
	return m, nil
}
func model(path string) ([]byte, error) {
	s, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if s.Mode().Perm()&0077 != 0 || !s.Mode().IsRegular() {
		return nil, errors.New("private model permissions required")
	}
	if s.Size() != 4184 {
		return nil, errors.New("recoverable IPA requires a v2 model")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	if len(b) != 4184 || string(b[:8]) != "FPSENR2\x00" || binary.LittleEndian.Uint32(b[8:]) != 2 || int(binary.LittleEndian.Uint32(b[12:])) != len(b) {
		return nil, errors.New("recoverable IPA requires a v2 model")
	}
	for p := 0; p < 16; p++ {
		seen := [256]bool{}
		for _, v := range b[88+p*256 : 88+(p+1)*256] {
			if seen[v] {
				return nil, errors.New("invalid model permutation")
			}
			seen[v] = true
		}
	}
	return b, nil
}
func members(z *zip.ReadCloser) (map[string]*zip.File, error) {
	m := map[string]*zip.File{}
	for _, v := range z.File {
		if _, ok := m[v.Name]; ok {
			return nil, errors.New("duplicate ZIP member")
		}
		if strings.HasPrefix(v.Name, "/") || strings.Contains(v.Name, "\\") {
			return nil, errors.New("unsafe member")
		}
		for _, c := range strings.Split(v.Name, "/") {
			if c == ".." {
				return nil, errors.New("unsafe member")
			}
		}
		if v.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("symlink member")
		}
		m[v.Name] = v
	}
	return m, nil
}
func read(v *zip.File) ([]byte, error) {
	r, e := v.Open()
	if e != nil {
		return nil, e
	}
	defer r.Close()
	return io.ReadAll(r)
}

func makeAtom(name string, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(b, uint32(len(b)))
	copy(b[4:8], name)
	copy(b[8:], payload)
	return b
}
func newSINF(p []byte, metadata applicationMetadata) ([]byte, error) {
	if e := metadata.validate(); e != nil {
		return nil, e
	}
	appkey, rights := metadata.ContentKey, metadata.bytes()
	// Only personalized fields are synthesized. Observed shared source fields
	// are restored exactly, including private IV and the rights trailer.
	var plain []byte
	for _, v := range []struct {
		k string
		b []byte
	}{{"key ", appkey}, {"iviv", metadata.PrivateIV}, {"tmpr", make([]byte, 16)}, {"righ", rights}, {"name", make([]byte, 256)}} {
		plain = append(plain, makeAtom(v.k, v.b)...)
	}
	var scheme []byte
	for _, v := range []struct {
		k string
		b []byte
	}{{"user", make([]byte, 4)}, {"key ", make([]byte, 4)}, {"iviv", make([]byte, 16)}, {"righ", rights}, {"name", make([]byte, 256)}, {"priv", make([]byte, 16+len(plain))}} {
		scheme = append(scheme, makeAtom(v.k, v.b)...)
	}
	outer := append(makeAtom("frma", metadata.Format), makeAtom("schm", metadata.Scheme)...)
	outer = append(outer, makeAtom("schi", scheme)...)
	outer = append(outer, makeAtom("sign", make([]byte, 128))...)
	source := makeAtom("sinf", outer)
	var logical [16]byte
	for i := 0; i < 4; i++ {
		v := binary.BigEndian.Uint32(appkey[i*4:])
		v += uint32(i+13) * 0xa6b13d89
		binary.LittleEndian.PutUint32(logical[i*4:], v)
	}
	return rewrap(source, p, license{PrivatePlaintext: plain, SourceSHA256: hash(source), LogicalKeySHA256: hash(logical[:])})
}

func encryptInto(input, mp, out string) error {
	p, e := model(mp)
	if e != nil {
		return e
	}
	defer clear(p)
	z, e := zip.OpenReader(input)
	if e != nil {
		return e
	}
	ms, e := members(z)
	if e != nil {
		z.Close()
		return e
	}
	if e := f.OmitAppleDoubleSidecars(ms); e != nil {
		z.Close()
		return e
	}
	recoveryPath, e := recoveryMemberPath(ms)
	if e != nil {
		z.Close()
		return e
	}
	file := ms[recoveryPath]
	if file == nil || file.UncompressedSize64 > 4096 {
		z.Close()
		return errors.New("missing or oversized .sinf-recovery; regenerate with decrypt-recoverable")
	}
	data, e := read(file)
	z.Close()
	if e != nil {
		return e
	}
	defer clear(data)
	metadata, e := decodeMetadata(data)
	if e != nil {
		return e
	}
	defer metadata.clearSecrets()
	sinf, e := newSINF(p, metadata)
	if e != nil {
		return e
	}
	defer clear(sinf)
	encrypted := filepath.Join(out, "restored.ipa")
	if e = f.RestoreRecoverableContent(input, encrypted, metadata.ContentKey, sinf); e != nil {
		return e
	}
	tmp, e := os.MkdirTemp(out, ".verify-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	r, e := f.DecryptIPA(f.DecryptOptions{InputPath: encrypted, ModelPath: mp, OutputPath: filepath.Join(tmp, "plain.ipa"), ReportPath: filepath.Join(tmp, "report.json")})
	if e != nil {
		return e
	}
	if !r.PlaintextVerified {
		return errors.New("plaintext unavailable")
	}
	return nil
}

func pack(input, mp, output string) (err error) {
	protected, e := f.UnencryptedBundles(input)
	if e != nil {
		return e
	}
	p, e := model(mp)
	if e != nil {
		return e
	}
	defer clear(p)
	tmp, e := os.MkdirTemp(filepath.Dir(output), ".minimal-pack-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	plain := filepath.Join(tmp, "plain.ipa")
	result, e := f.DecryptIPA(f.DecryptOptions{InputPath: input, ModelPath: mp, OutputPath: plain, ReportPath: filepath.Join(tmp, "report.json")})
	if e != nil {
		return e
	}
	if !result.PlaintextVerified {
		return errors.New("complete plaintext coverage required")
	}
	z, e := zip.OpenReader(plain)
	if e != nil {
		return e
	}
	defer z.Close()
	ms, e := members(z)
	if e != nil {
		return e
	}
	if e := f.OmitAppleDoubleSidecars(ms); e != nil {
		return e
	}
	recoveryPath, e := recoveryMemberPath(ms)
	if e != nil {
		return e
	}
	if ms[recoveryPath] != nil {
		return errors.New("existing SINF recovery material")
	}
	var metadata applicationMetadata
	defer metadata.clearSecrets()
	count := 0
	for name, v := range ms {
		if !strings.HasSuffix(name, ".sinf") {
			continue
		}
		b, e := read(v)
		if e != nil {
			return e
		}
		if name != strings.TrimSuffix(recoveryPath, "-recovery") {
			return errors.New("source SINF route does not match main executable")
		}
		metadata, e = extractMetadata(b, p)
		if e != nil {
			return e
		}
		count++
	}
	if count != 1 {
		return errors.New("one source SINF required")
	}
	out, e := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer func() {
		out.Close()
		if err != nil {
			os.Remove(output)
		}
	}()
	w := zip.NewWriter(out)
	for _, v := range z.File {
		n := v.Name
		if ms[n] == nil {
			continue
		}
		keep := false
		for _, prefix := range protected {
			if strings.HasPrefix(n, prefix) {
				keep = true
			}
		}
		if keep {
			if e = w.Copy(v); e != nil {
				return e
			}
			continue
		}
		if v.FileInfo().IsDir() || strings.HasSuffix(n, ".sinf") || strings.EqualFold(filepath.Base(n), "iTunesMetadata.plist") {
			continue
		}
		skip := false
		for _, c := range strings.Split(n, "/") {
			if c == "_MASReceipt" {
				skip = true
			}
		}
		if skip {
			continue
		}
		data, e := read(v)
		if e != nil {
			return e
		}
		h := zip.FileHeader{Name: n, Method: zip.Deflate}
		mode := os.FileMode(0600)
		if v.Mode()&0111 != 0 {
			mode = 0700
		}
		h.SetMode(mode)
		dest, e := w.CreateHeader(&h)
		if e != nil {
			return e
		}
		if _, e = dest.Write(data); e != nil {
			return e
		}
	}
	data, e := json.Marshal(metadata)
	if e != nil {
		return e
	}
	defer clear(data)
	h := zip.FileHeader{Name: recoveryPath, Method: zip.Store}
	h.SetMode(0600)
	dest, e := w.CreateHeader(&h)
	if e != nil {
		return e
	}
	if _, e = dest.Write(data); e != nil {
		return e
	}
	if e = w.Close(); e != nil {
		return e
	}
	return out.Close()
}

func recoveryMemberPath(ms map[string]*zip.File) (string, error) {
	var result string
	for n := range ms {
		parts := strings.Split(n, "/")
		if len(parts) == 3 && parts[0] == "Payload" && strings.HasSuffix(parts[1], ".app") && parts[2] == "Info.plist" {
			if result != "" {
				return "", errors.New("multiple app roots")
			}
			if ms[n].UncompressedSize64 > 4<<20 {
				return "", errors.New("oversized main Info.plist")
			}
			data, e := read(ms[n])
			if e != nil {
				return "", e
			}
			var info struct {
				Executable string `plist:"CFBundleExecutable"`
			}
			if _, e = plist.Unmarshal(data, &info); e != nil {
				return "", e
			}
			exe := info.Executable
			if exe == "" || exe == "." || exe == ".." || strings.ContainsAny(exe, "/\\") {
				return "", errors.New("unsafe main executable name")
			}
			result = path.Join(path.Dir(n), "SC_Info", exe+recoverySuffix)
		}
	}
	if result == "" {
		return "", errors.New("missing main bundle")
	}
	for n := range ms {
		if path.Base(n) == "AppContentKey.bin" || path.Base(n) == "AppRecovery.json" || (strings.HasSuffix(n, recoverySuffix) && n != result) {
			return "", errors.New("unexpected key location")
		}
	}
	return result, nil
}

type license struct {
	SourceSHA256     string
	PrivatePlaintext []byte
	LogicalKeySHA256 string
}

func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func rewrap(s, p []byte, l license) ([]byte, error) {
	if hash(s) != l.SourceSHA256 {
		return nil, errors.New("SINF source mismatch")
	}
	out := bytes.Clone(s)
	m, e := fields(out)
	if e != nil {
		return nil, e
	}
	v := out[m["priv"].start:m["priv"].end]
	if len(v) != len(l.PrivatePlaintext)+16 {
		return nil, errors.New("private payload length")
	}
	n := len(l.PrivatePlaintext) / 16 * 16
	tail := len(l.PrivatePlaintext) - n
	if tail != 0 && tail != 8 {
		return nil, errors.New("private trailer")
	}
	for _, x := range l.PrivatePlaintext[n:] {
		if x != 0 {
			return nil, errors.New("private trailer nonzero")
		}
	}
	raw := make([]byte, 16+n)
	defer clear(raw)
	// The leading block is encrypted itun/vers, not a free random CBC IV.
	// Randomize the visible IV, then encrypt the complete record from its
	// name/iviv-derived IV so native consumers can validate the header too.
	ivField, ok := m["iviv"]
	if !ok || ivField.end-ivField.start != 16 {
		return nil, errors.New("visible IV geometry")
	}
	if _, e = rand.Read(out[ivField.start:ivField.end]); e != nil {
		return nil, e
	}
	iv, e := privateRecordIV(out, m)
	if e != nil {
		return nil, e
	}
	block, e := aes.NewCipher(p[56:72])
	if e != nil {
		return nil, e
	}
	complete := make([]byte, 16+n)
	defer clear(complete)
	copy(complete, privateRecordHeader[:])
	copy(complete[16:], l.PrivatePlaintext[:n])
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(raw, complete)
	for i, x := range raw {
		pos := i % 16
		for j := 0; j < 256; j++ {
			if p[88+pos*256+j] == x {
				v[i] = byte(j) ^ p[72+pos]
				break
			}
		}
	}
	copy(v[16+n:], l.PrivatePlaintext[n:])
	for _, k := range []string{"user", "key "} {
		if m[k].end-m[k].start != 4 {
			return nil, errors.New("selector geometry")
		}
	}
	binary.BigEndian.PutUint32(out[m["user"].start:], binary.LittleEndian.Uint32(p[48:52]))
	binary.BigEndian.PutUint32(out[m["key "].start:], binary.LittleEndian.Uint32(p[52:56]))
	if e = validatePrivateRecordHeader(out, p, m); e != nil {
		return nil, e
	}
	key, e := f.ResolveLogicalKeyWithModel(out, p)
	if e != nil {
		return nil, errors.New("rewrapped SINF validation failed")
	}
	defer clear(key.LogicalKey[:])
	if hash(key.LogicalKey[:]) != l.LogicalKeySHA256 {
		return nil, errors.New("content key changed")
	}
	return out, nil
}
