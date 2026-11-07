package fairplay

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"howett.net/plist"
)

const maximumMacOSSINFBytes = 1024 * 1024

// MacOSPrepareOptions configures offline conversion of personalized SINF
// records into the legacy layout accepted by macOS FairPlay.
type MacOSPrepareOptions struct {
	InputPath      string
	OutputPath     string
	CredentialPath string
	ModelPath      string
	Force          bool
}

type MacOSSINFRecordReport struct {
	Path                        string `json:"path"`
	ReplicatedFrom              string `json:"replicated_from,omitempty"`
	InputBytes                  int    `json:"input_bytes"`
	OutputBytes                 int    `json:"output_bytes"`
	OriginalMode                uint32 `json:"original_mode"`
	ConvertedMode               uint32 `json:"converted_mode"`
	NamedRightsPreserved        int    `json:"named_rights_preserved"`
	RightsSuffixRemovedBytes    int    `json:"rights_suffix_removed_bytes"`
	PrivateKeyMaterialPreserved bool   `json:"private_key_material_preserved"`
}

type macOSSINFManifest struct {
	SINFPaths            []string `plist:"SinfPaths,omitempty"`
	SINFReplicationPaths []string `plist:"SinfReplicationPaths,omitempty"`
}

type macOSSINFReplica struct {
	data   []byte
	header zip.FileHeader
}

type MacOSPrepareResult struct {
	Schema        string                  `json:"schema"`
	OutputPath    string                  `json:"output_path"`
	InputSHA256   string                  `json:"input_sha256"`
	OutputSHA256  string                  `json:"output_sha256"`
	Records       []MacOSSINFRecordReport `json:"records"`
	MachOModified bool                    `json:"mach_o_modified"`
}

func macOSSINFAtom(typ string, payload []byte) []byte {
	result := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(result[:4], uint32(len(result)))
	copy(result[4:8], typ)
	copy(result[8:], payload)
	return result
}

func macOSSINFField(blob []byte, fields []sinfAtom, typ string) ([]byte, error) {
	field, err := uniqueAtom(fields, typ)
	if err != nil {
		return nil, err
	}
	return blob[field.start:field.end], nil
}

func macOSSINFRightsValue(rights []byte, typ string) (int, error) {
	found := -1
	for offset := 0; offset+8 <= len(rights); offset += 8 {
		if string(rights[offset:offset+4]) != typ {
			continue
		}
		if found >= 0 {
			return 0, fmt.Errorf("SINF rights contain duplicate %q entries", typ)
		}
		found = offset + 4
	}
	if found < 0 {
		return 0, fmt.Errorf("SINF rights require one %q entry", typ)
	}
	return found, nil
}

func macOSSINFCrypt(input, credential, name, iviv []byte, encrypt bool) ([]byte, error) {
	if len(input)%aes.BlockSize != 0 || len(credential) != aes.BlockSize || len(iviv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid macOS SINF AES-CBC geometry")
	}
	key := make([]byte, aes.BlockSize)
	for index, value := range credential {
		key[index] = value ^ 0x30
	}
	defer clear(key)
	nameEnd := bytes.IndexByte(name, 0)
	if nameEnd < 0 {
		nameEnd = len(name)
	}
	ivSource := make([]byte, 0, nameEnd+len(iviv))
	ivSource = append(ivSource, name[:nameEnd]...)
	ivSource = append(ivSource, iviv...)
	iv := md5.Sum(ivSource)
	clear(ivSource)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	output := make([]byte, len(input))
	if encrypt {
		cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(output, input)
	} else {
		cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(output, input)
	}
	return output, nil
}

func validateMacOSSINFPrivate(cleartext, visibleRights []byte) ([]sinfAtom, error) {
	if len(cleartext) < 64 || string(cleartext[:4]) != "itun" ||
		string(cleartext[20:24]) != "key " || string(cleartext[44:48]) != "iviv" {
		return nil, fmt.Errorf("credential does not decode the SINF private record")
	}
	fields, err := sinfAtoms(cleartext, 16, len(cleartext))
	if err != nil {
		return nil, fmt.Errorf("parse SINF private record: %w", err)
	}
	expected := [...]string{"key ", "iviv", "tmpr", "righ", "name"}
	if len(fields) != len(expected) {
		return nil, fmt.Errorf("SINF private record has unexpected fields")
	}
	for index, typ := range expected {
		if fields[index].typ != typ {
			return nil, fmt.Errorf("SINF private record field %d is %q, want %q", index, fields[index].typ, typ)
		}
	}
	expectedBytes := map[string]int{"key ": 16, "iviv": 16, "tmpr": 16, "righ": len(visibleRights), "name": 256}
	for _, field := range fields {
		if field.end-field.start != expectedBytes[field.typ] {
			return nil, fmt.Errorf("SINF private %q field has invalid geometry", field.typ)
		}
	}
	privateRights, err := macOSSINFField(cleartext, fields, "righ")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(privateRights, visibleRights) {
		return nil, fmt.Errorf("SINF visible and private rights differ")
	}
	return fields, nil
}

func verifyMacOSSINF(blob, credential []byte) error {
	fields, err := parseSINFFields(blob)
	if err != nil {
		return err
	}
	expected := [...]string{"user", "crdt", "asdt", "key ", "iviv", "righ", "name", "priv"}
	if len(fields) != len(expected) {
		return fmt.Errorf("converted SINF has unexpected fields")
	}
	for index, typ := range expected {
		if fields[index].typ != typ {
			return fmt.Errorf("converted SINF field %d is %q, want %q", index, fields[index].typ, typ)
		}
	}
	rights, err := macOSSINFField(blob, fields, "righ")
	if err != nil {
		return err
	}
	name, err := macOSSINFField(blob, fields, "name")
	if err != nil {
		return err
	}
	iviv, err := macOSSINFField(blob, fields, "iviv")
	if err != nil {
		return err
	}
	private, err := macOSSINFField(blob, fields, "priv")
	if err != nil {
		return err
	}
	user, userErr := macOSSINFField(blob, fields, "user")
	keyID, keyErr := macOSSINFField(blob, fields, "key ")
	crdt, crdtErr := macOSSINFField(blob, fields, "crdt")
	asdt, asdtErr := macOSSINFField(blob, fields, "asdt")
	if userErr != nil || keyErr != nil || crdtErr != nil || asdtErr != nil ||
		len(user) != 4 || len(keyID) != 4 || len(crdt) != 4 || len(asdt) != 4 ||
		len(iviv) != 16 || len(name) != 256 || len(rights) != 80 || len(private) != 440 ||
		!bytes.Equal(asdt, make([]byte, 4)) || !bytes.Equal(private[len(private)-8:], make([]byte, 8)) {
		return fmt.Errorf("converted SINF has invalid legacy geometry")
	}
	cleartext, err := macOSSINFCrypt(private[:len(private)-8], credential, name, iviv, false)
	if err != nil {
		return err
	}
	cleartext = append(cleartext, private[len(private)-8:]...)
	defer clear(cleartext)
	if _, err := validateMacOSSINFPrivate(cleartext, rights); err != nil {
		return err
	}
	roundTrip, err := macOSSINFCrypt(cleartext[:len(cleartext)-8], credential, name, iviv, true)
	if err != nil {
		return err
	}
	defer clear(roundTrip)
	if !bytes.Equal(roundTrip, private[:len(private)-8]) {
		return fmt.Errorf("converted SINF private record does not round trip")
	}
	return nil
}

func normalizeMacOSSINF(blob, credential []byte) ([]byte, MacOSSINFRecordReport, error) {
	var report MacOSSINFRecordReport
	if len(credential) != aes.BlockSize {
		return nil, report, fmt.Errorf("macOS FairPlay credential must contain exactly 16 bytes")
	}
	roots, err := sinfAtoms(blob, 0, len(blob))
	if err != nil {
		return nil, report, err
	}
	if len(roots) != 1 || roots[0].typ != "sinf" || roots[0].start != 8 || roots[0].end != len(blob) {
		return nil, report, fmt.Errorf("SINF must contain one complete root atom")
	}
	outer, err := sinfAtoms(blob, roots[0].start, roots[0].end)
	if err != nil {
		return nil, report, err
	}
	schi, err := uniqueAtom(outer, "schi")
	if err != nil {
		return nil, report, err
	}
	fields, err := sinfAtoms(blob, schi.start, schi.end)
	if err != nil {
		return nil, report, err
	}
	requiredFields := [...]string{"user", "key ", "iviv", "righ", "name", "priv"}
	allowedFields := map[string]bool{
		"user": true, "key ": true, "iviv": true, "righ": true, "name": true, "priv": true,
		"crdt": true, "asdt": true,
	}
	values := make(map[string][]byte, len(fields)+2)
	for _, field := range fields {
		if !allowedFields[field.typ] {
			return nil, report, fmt.Errorf("unsupported current SINF field %q", field.typ)
		}
		if _, exists := values[field.typ]; exists {
			return nil, report, fmt.Errorf("duplicate current SINF field %q", field.typ)
		}
		values[field.typ] = blob[field.start:field.end]
	}
	for _, typ := range requiredFields {
		if _, ok := values[typ]; !ok {
			return nil, report, fmt.Errorf("current SINF does not contain required field %q", typ)
		}
	}
	for _, typ := range [...]string{"crdt", "asdt"} {
		if value := values[typ]; value != nil && len(value) != 4 {
			return nil, report, fmt.Errorf("current SINF optional field %q has invalid geometry", typ)
		}
	}
	rights := values["righ"]
	namedRightsBytes, err := currentSINFRightsGeometry(rights)
	if err != nil {
		return nil, report, err
	}
	privateBytes := 360 + len(rights)
	if len(values["user"]) != 4 || len(values["key "]) != 4 || len(values["iviv"]) != aes.BlockSize ||
		len(values["name"]) != 256 || len(values["priv"]) != privateBytes {
		return nil, report, fmt.Errorf("current SINF has unsupported IV or private-record geometry")
	}
	trailerBytes := privateBytes % aes.BlockSize
	if trailerBytes != 0 && trailerBytes != 8 {
		return nil, report, fmt.Errorf("current SINF private record has invalid trailer geometry")
	}
	encryptedPrivate := values["priv"][:privateBytes-trailerBytes]
	for _, value := range values["priv"][privateBytes-trailerBytes:] {
		if value != 0 {
			return nil, report, fmt.Errorf("current SINF private record has nonzero trailer")
		}
	}
	cleartext, err := macOSSINFCrypt(encryptedPrivate, credential, values["name"], values["iviv"], false)
	if err != nil {
		return nil, report, err
	}
	cleartext = append(cleartext, values["priv"][privateBytes-trailerBytes:]...)
	defer clear(cleartext)
	privateFields, err := validateMacOSSINFPrivate(cleartext, rights)
	if err != nil {
		return nil, report, err
	}
	roundTrip, err := macOSSINFCrypt(cleartext[:len(cleartext)-trailerBytes], credential, values["name"], values["iviv"], true)
	if err != nil {
		return nil, report, err
	}
	if !bytes.Equal(roundTrip, encryptedPrivate) {
		clear(roundTrip)
		return nil, report, fmt.Errorf("current SINF private record does not round trip")
	}
	clear(roundTrip)

	modeAt, err := macOSSINFRightsValue(rights[:namedRightsBytes], "mode")
	if err != nil {
		return nil, report, err
	}
	originalMode := binary.BigEndian.Uint32(rights[modeAt : modeAt+4])
	normalizedRights := make([]byte, 80)
	copy(normalizedRights, rights[:min(namedRightsBytes, len(normalizedRights))])
	binary.BigEndian.PutUint32(normalizedRights[modeAt:modeAt+4], 0)

	normalizedClear := append([]byte(nil), cleartext[:16]...)
	for _, field := range privateFields {
		payload := cleartext[field.start:field.end]
		if field.typ == "righ" {
			payload = normalizedRights
		}
		normalizedClear = append(normalizedClear, macOSSINFAtom(field.typ, payload)...)
	}
	defer clear(normalizedClear)
	if len(normalizedClear) != 440 || !bytes.Equal(normalizedClear[len(normalizedClear)-8:], make([]byte, 8)) {
		return nil, report, fmt.Errorf("legacy SINF private record has invalid geometry")
	}
	private, err := macOSSINFCrypt(normalizedClear[:len(normalizedClear)-8], credential, values["name"], values["iviv"], true)
	if err != nil {
		return nil, report, err
	}
	private = append(private, normalizedClear[len(normalizedClear)-8:]...)
	defer clear(private)
	tranAt, err := macOSSINFRightsValue(rights[:namedRightsBytes], "tran")
	if err != nil {
		return nil, report, err
	}
	values["crdt"] = append([]byte(nil), rights[tranAt:tranAt+4]...)
	values["asdt"] = make([]byte, 4)
	values["righ"] = normalizedRights
	values["priv"] = private
	order := [...]string{"user", "crdt", "asdt", "key ", "iviv", "righ", "name", "priv"}
	var scheme []byte
	for _, typ := range order {
		scheme = append(scheme, macOSSINFAtom(typ, values[typ])...)
	}
	var rootPayload []byte
	for _, field := range outer {
		payload := blob[field.start:field.end]
		if field.typ == "schi" {
			payload = scheme
		}
		rootPayload = append(rootPayload, macOSSINFAtom(field.typ, payload)...)
	}
	result := macOSSINFAtom("sinf", rootPayload)
	if err := verifyMacOSSINF(result, credential); err != nil {
		clear(result)
		return nil, report, fmt.Errorf("verify converted SINF: %w", err)
	}
	for _, typ := range []string{"key ", "iviv", "tmpr", "name"} {
		before, fieldErr := macOSSINFField(cleartext, privateFields, typ)
		if fieldErr != nil {
			clear(result)
			return nil, report, fieldErr
		}
		afterFields, fieldErr := sinfAtoms(normalizedClear, 16, len(normalizedClear))
		if fieldErr != nil {
			clear(result)
			return nil, report, fieldErr
		}
		after, fieldErr := macOSSINFField(normalizedClear, afterFields, typ)
		if fieldErr != nil || !bytes.Equal(before, after) {
			clear(result)
			return nil, report, fmt.Errorf("converted SINF changed private %q material", typ)
		}
	}
	report = MacOSSINFRecordReport{
		InputBytes: len(blob), OutputBytes: len(result), OriginalMode: originalMode,
		ConvertedMode: 0, NamedRightsPreserved: min(namedRightsBytes/8, len(normalizedRights)/8),
		RightsSuffixRemovedBytes: len(rights) - len(normalizedRights), PrivateKeyMaterialPreserved: true,
	}
	return result, report, nil
}

func replaceCurrentSINFPrivate(blob, private []byte) ([]byte, error) {
	roots, err := sinfAtoms(blob, 0, len(blob))
	if err != nil || len(roots) != 1 || roots[0].typ != "sinf" || roots[0].start != 8 || roots[0].end != len(blob) {
		return nil, fmt.Errorf("SINF must contain one complete root atom")
	}
	outer, err := sinfAtoms(blob, roots[0].start, roots[0].end)
	if err != nil {
		return nil, err
	}
	schi, err := uniqueAtom(outer, "schi")
	if err != nil {
		return nil, err
	}
	fields, err := sinfAtoms(blob, schi.start, schi.end)
	if err != nil {
		return nil, err
	}
	if _, err := uniqueAtom(fields, "priv"); err != nil {
		return nil, err
	}
	var scheme []byte
	for _, field := range fields {
		payload := blob[field.start:field.end]
		if field.typ == "priv" {
			payload = private
		}
		scheme = append(scheme, macOSSINFAtom(field.typ, payload)...)
	}
	var rootPayload []byte
	for _, field := range outer {
		payload := blob[field.start:field.end]
		if field.typ == "schi" {
			payload = scheme
		}
		rootPayload = append(rootPayload, macOSSINFAtom(field.typ, payload)...)
	}
	clear(scheme)
	result := macOSSINFAtom("sinf", rootPayload)
	clear(rootPayload)
	return result, nil
}

func normalizeMacOSSINFWithModel(blob []byte, model currentSINFModel) ([]byte, MacOSSINFRecordReport, error) {
	var report MacOSSINFRecordReport
	if model.version != 2 || !model.hasSelector {
		return nil, report, fmt.Errorf("macOS conversion requires a selector-bound version-2 model")
	}
	fields, err := parseSINFFields(blob)
	if err != nil {
		return nil, report, err
	}
	selector, err := sinfSelector(blob, fields)
	if err != nil {
		return nil, report, err
	}
	if selector != model.selector {
		return nil, report, fmt.Errorf("enrollment model selector does not match SINF selector %s", selector.Identifier())
	}
	source, err := sinfPrivatePayload(blob, fields)
	if err != nil {
		return nil, report, err
	}
	atoms, err := currentSINFPrivatePlaintextLegacy(model, source)
	if err != nil {
		return nil, report, err
	}
	defer clear(atoms)
	cleartext := make([]byte, 16, 16+len(atoms))
	copy(cleartext, "itun")
	binary.BigEndian.PutUint32(cleartext[4:8], 12)
	copy(cleartext[8:12], "vers")
	binary.BigEndian.PutUint32(cleartext[12:16], 1)
	cleartext = append(cleartext, atoms...)
	defer clear(cleartext)
	trailerBytes := len(cleartext) % aes.BlockSize
	for _, value := range cleartext[len(cleartext)-trailerBytes:] {
		if value != 0 {
			return nil, report, fmt.Errorf("current SINF decoded private trailer is not zero")
		}
	}
	name, err := macOSSINFField(blob, fields, "name")
	if err != nil {
		return nil, report, err
	}
	iviv, err := macOSSINFField(blob, fields, "iviv")
	if err != nil {
		return nil, report, err
	}
	credential := make([]byte, aes.BlockSize)
	for position, value := range model.key {
		credential[position] = value ^ 0x30
	}
	defer clear(credential)
	private, err := macOSSINFCrypt(cleartext[:len(cleartext)-trailerBytes], credential, name, iviv, true)
	if err != nil {
		return nil, report, err
	}
	private = append(private, cleartext[len(cleartext)-trailerBytes:]...)
	defer clear(private)
	rewritten, err := replaceCurrentSINFPrivate(blob, private)
	if err != nil {
		return nil, report, err
	}
	defer clear(rewritten)
	return normalizeMacOSSINF(rewritten, credential)
}

func normalizeMacOSSINFWithModels(blob []byte, packs [][]byte) ([]byte, MacOSSINFRecordReport, error) {
	var selected []byte
	var selectedReport MacOSSINFRecordReport
	selector, err := ParseSINFSelector(blob)
	if err != nil {
		return nil, selectedReport, err
	}
	matching := 0
	var lastError error
	for index, pack := range packs {
		model, parseErr := parseCurrentSINFModel(pack)
		if parseErr != nil {
			clear(selected)
			return nil, selectedReport, fmt.Errorf("parse FairPlay model %d: %w", index, parseErr)
		}
		// Version 3 uses another protected codec and is rejected until the same
		// conversion relation is independently proven there.
		if model.version != 2 || !model.hasSelector || model.selector != selector {
			continue
		}
		matching++
		converted, report, convertErr := normalizeMacOSSINFWithModel(blob, model)
		directErr := convertErr
		if convertErr != nil {
			// Version-2 models produced before direct enrollment stored the same
			// AES key but were paired with the legacy private-record wrapper.
			credential := make([]byte, aes.BlockSize)
			for position, value := range model.key {
				credential[position] = value ^ 0x30
			}
			converted, report, convertErr = normalizeMacOSSINF(blob, credential)
			clear(credential)
		}
		if convertErr != nil {
			lastError = fmt.Errorf("direct model: %v; legacy wrapper: %v", directErr, convertErr)
			continue
		}
		if selected != nil {
			clear(selected)
			clear(converted)
			return nil, selectedReport, fmt.Errorf("multiple enrollment models decode SINF selector %s", selector.Identifier())
		}
		selected, selectedReport = converted, report
	}
	if selected != nil {
		return selected, selectedReport, nil
	}
	if matching == 0 {
		return nil, selectedReport, fmt.Errorf("no version-2 enrollment model matches SINF selector %s", selector.Identifier())
	}
	return nil, selectedReport, fmt.Errorf("matching enrollment model cannot derive the macOS credential for SINF selector %s: %v", selector.Identifier(), lastError)
}

func macOSSINFMember(root, relative string) (string, error) {
	if relative == "" || path.IsAbs(relative) || strings.Contains(relative, "\\") {
		return "", fmt.Errorf("unsafe SINF replication path %q", relative)
	}
	clean := path.Clean(relative)
	if clean != relative || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") ||
		!strings.HasSuffix(strings.ToLower(clean), ".sinf") || !strings.Contains("/"+clean, "/SC_Info/") {
		return "", fmt.Errorf("unsafe SINF replication path %q", relative)
	}
	member := path.Join(root, clean)
	if !strings.HasPrefix(member, root+"/") {
		return "", fmt.Errorf("SINF replication path escapes its app bundle: %q", relative)
	}
	return member, nil
}

func addMacOSSINFReplicas(source *zip.ReadCloser, files map[string]*zip.File,
	replacements map[string][]byte, reportsByPath map[string]MacOSSINFRecordReport,
) (map[string]macOSSINFReplica, []MacOSSINFRecordReport, error) {
	replicas := make(map[string]macOSSINFReplica)
	var reports []MacOSSINFRecordReport
	for _, file := range source.File {
		const suffix = "/SC_Info/Manifest.plist"
		if !strings.HasSuffix(file.Name, suffix) {
			continue
		}
		data, err := zipBytes(file)
		if err != nil {
			return nil, nil, err
		}
		var manifest macOSSINFManifest
		_, err = plist.Unmarshal(data, &manifest)
		clear(data)
		if err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", file.Name, err)
		}
		if len(manifest.SINFReplicationPaths) == 0 {
			continue
		}
		root := strings.TrimSuffix(file.Name, suffix)
		sources, err := loadManifestSINFSources(files, root, file.Name, manifest.SINFPaths)
		if err != nil {
			return nil, nil, err
		}
		manifestErr := func() error {
			defer clearManifestSINFSources(sources)
			for _, relative := range manifest.SINFReplicationPaths {
				target, pathErr := macOSSINFMember(root, relative)
				if pathErr != nil {
					return fmt.Errorf("%s: %w", file.Name, pathErr)
				}
				var targetData []byte
				targetFile, targetPresent := files[target]
				if targetPresent {
					if targetFile == nil {
						return fmt.Errorf("invalid target SINF %q", target)
					}
					targetData, err = zipBytes(targetFile)
					if err != nil {
						return fmt.Errorf("read target SINF %q: %w", target, err)
					}
				}
				source, selectErr := selectManifestSINFSource(sources, target, targetData, targetPresent)
				clear(targetData)
				if selectErr != nil {
					return fmt.Errorf("%s: %w", file.Name, selectErr)
				}
				if target == source.name {
					continue
				}
				converted, ok := replacements[source.name]
				if !ok {
					return fmt.Errorf("%s source SINF %q was not converted", file.Name, source.name)
				}
				if existing, exists := replacements[target]; exists {
					if !bytes.Equal(existing, converted) {
						return fmt.Errorf("replicated SINF %q differs from source %q", target, source.name)
					}
					continue
				}
				if targetPresent {
					return fmt.Errorf("existing SINF %q was not converted", target)
				}
				if existing, exists := replicas[target]; exists {
					if !bytes.Equal(existing.data, converted) {
						return fmt.Errorf("conflicting SINF replication target %q", target)
					}
					continue
				}
				header := source.file.FileHeader
				header.Name = target
				replicas[target] = macOSSINFReplica{data: converted, header: header}
				report := reportsByPath[source.name]
				report.Path = target
				report.ReplicatedFrom = source.name
				reports = append(reports, report)
			}
			return nil
		}()
		if manifestErr != nil {
			return nil, nil, manifestErr
		}
	}
	return replicas, reports, nil
}

func validateMacOSPreparePaths(options MacOSPrepareOptions) (MacOSPrepareOptions, error) {
	if err := checkPlatform(); err != nil {
		return options, err
	}
	if (options.CredentialPath == "") == (options.ModelPath == "") {
		return options, fmt.Errorf("provide exactly one macOS FairPlay credential or enrollment model")
	}
	type prepareInput struct {
		value          *string
		allowDirectory bool
	}
	inputs := []prepareInput{{&options.InputPath, false}}
	if options.CredentialPath != "" {
		inputs = append(inputs, prepareInput{&options.CredentialPath, false})
	} else {
		inputs = append(inputs, prepareInput{&options.ModelPath, true})
	}
	for _, input := range inputs {
		resolved, err := canonicalPath(*input.value)
		if err != nil {
			return options, err
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return options, err
		}
		if !input.allowDirectory && !info.Mode().IsRegular() {
			return options, fmt.Errorf("macOS preparation input must be a regular file: %s", resolved)
		}
		if input.allowDirectory && !info.Mode().IsRegular() && !info.IsDir() {
			return options, fmt.Errorf("macOS preparation model must be a regular file or directory: %s", resolved)
		}
		*input.value = resolved
	}
	if options.CredentialPath != "" {
		credentialInfo, err := os.Stat(options.CredentialPath)
		if err != nil {
			return options, err
		}
		if credentialInfo.Mode().Perm()&0o077 != 0 {
			return options, fmt.Errorf("macOS FairPlay credential must not be accessible by group or other users")
		}
	}
	info, err := os.Lstat(options.OutputPath)
	if err != nil && !os.IsNotExist(err) {
		return options, err
	}
	if err == nil && !info.Mode().IsRegular() {
		return options, fmt.Errorf("macOS preparation output must be a regular file, not a symlink or directory")
	}
	resolved, err := canonicalPath(options.OutputPath)
	if err != nil {
		return options, err
	}
	for _, input := range inputs {
		if pathsAlias(resolved, *input.value) {
			return options, fmt.Errorf("refusing to overwrite macOS preparation input or private state")
		}
	}
	if info != nil && !options.Force {
		return options, fmt.Errorf("refusing to replace %s", resolved)
	}
	options.OutputPath = resolved
	return options, nil
}

// PrepareMacOSIPA converts every supported personalized SINF in an IPA. It
// leaves all Mach-O files byte-identical and does not change their encryption.
func PrepareMacOSIPA(options MacOSPrepareOptions) (MacOSPrepareResult, error) {
	var result MacOSPrepareResult
	options, err := validateMacOSPreparePaths(options)
	if err != nil {
		return result, err
	}
	var credential []byte
	var packs [][]byte
	if options.CredentialPath != "" {
		credential, err = os.ReadFile(options.CredentialPath)
		if err != nil {
			return result, fmt.Errorf("read macOS FairPlay credential: %w", err)
		}
		defer clear(credential)
		if len(credential) != aes.BlockSize {
			return result, fmt.Errorf("macOS FairPlay credential must contain exactly 16 bytes")
		}
	} else {
		info, statErr := os.Stat(options.ModelPath)
		if statErr != nil {
			return result, statErr
		}
		if info.IsDir() {
			packs, err = readEnrollmentModelRegistry(options.ModelPath)
		} else {
			var pack []byte
			pack, err = readEnrollmentModel(options.ModelPath)
			if err == nil {
				packs = [][]byte{pack}
			}
		}
		if err != nil {
			return result, err
		}
		defer clearModelPacks(packs)
	}
	inputHash, err := fileSHA256(options.InputPath)
	if err != nil {
		return result, err
	}
	source, err := zip.OpenReader(options.InputPath)
	if err != nil {
		return result, err
	}
	defer source.Close()
	seen := make(map[string]bool, len(source.File))
	files := make(map[string]*zip.File, len(source.File))
	replacements := make(map[string][]byte)
	defer func() {
		for _, replacement := range replacements {
			clear(replacement)
		}
	}()
	var reports []MacOSSINFRecordReport
	reportsByPath := make(map[string]MacOSSINFRecordReport)
	for _, file := range source.File {
		if seen[file.Name] {
			return result, fmt.Errorf("IPA contains duplicate ZIP member %q", file.Name)
		}
		seen[file.Name] = true
		files[file.Name] = file
		if !strings.Contains(file.Name, "/SC_Info/") || !strings.HasSuffix(strings.ToLower(file.Name), ".sinf") {
			continue
		}
		if file.UncompressedSize64 > maximumMacOSSINFBytes {
			return result, fmt.Errorf("SINF %q exceeds the %d-byte limit", file.Name, maximumMacOSSINFBytes)
		}
		blob, readErr := zipBytes(file)
		if readErr != nil {
			return result, readErr
		}
		var converted []byte
		var report MacOSSINFRecordReport
		var convertErr error
		if credential != nil {
			converted, report, convertErr = normalizeMacOSSINF(blob, credential)
		} else {
			converted, report, convertErr = normalizeMacOSSINFWithModels(blob, packs)
		}
		clear(blob)
		if convertErr != nil {
			return result, fmt.Errorf("convert %s: %w", file.Name, convertErr)
		}
		report.Path = file.Name
		replacements[file.Name] = converted
		reports = append(reports, report)
		reportsByPath[file.Name] = report
	}
	if len(reports) == 0 {
		return result, fmt.Errorf("IPA contains no supported SINF records")
	}
	replicas, replicaReports, err := addMacOSSINFReplicas(source, files, replacements, reportsByPath)
	if err != nil {
		return result, err
	}
	reports = append(reports, replicaReports...)
	if err := os.MkdirAll(filepath.Dir(options.OutputPath), 0o700); err != nil {
		return result, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(options.OutputPath), ".unfairplay-macos-*.ipa")
	if err != nil {
		return result, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	defer temporary.Close()
	if err := temporary.Chmod(0o600); err != nil {
		return result, err
	}
	writer := zip.NewWriter(temporary)
	for _, file := range source.File {
		replacement, replace := replacements[file.Name]
		if !replace {
			if err := writer.Copy(file); err != nil {
				return result, err
			}
			continue
		}
		header := file.FileHeader
		target, err := writer.CreateHeader(&header)
		if err != nil {
			return result, err
		}
		if _, err := target.Write(replacement); err != nil {
			return result, err
		}
	}
	var replicaNames []string
	for name := range replicas {
		replicaNames = append(replicaNames, name)
	}
	sort.Strings(replicaNames)
	for _, name := range replicaNames {
		replica := replicas[name]
		target, err := writer.CreateHeader(&replica.header)
		if err != nil {
			return result, err
		}
		if _, err := target.Write(replica.data); err != nil {
			return result, err
		}
	}
	if err := writer.Close(); err != nil {
		return result, err
	}
	if err := temporary.Sync(); err != nil {
		return result, err
	}
	if err := temporary.Close(); err != nil {
		return result, err
	}
	outputHash, err := fileSHA256(temporaryPath)
	if err != nil {
		return result, err
	}
	if _, err := validateMacOSPreparePaths(options); err != nil {
		return result, err
	}
	if err := publishFiles([]stagedFile{{temporary: temporaryPath, destination: options.OutputPath}}, options.Force); err != nil {
		return result, err
	}
	return MacOSPrepareResult{
		Schema: "unfairplay-macos-preparation-v1", OutputPath: options.OutputPath,
		InputSHA256: inputHash, OutputSHA256: outputHash, Records: reports, MachOModified: false,
	}, nil
}
