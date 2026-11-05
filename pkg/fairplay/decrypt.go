package fairplay

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const pageBytes = 4096

type encryptedImage struct {
	member, supfMember, sinfMember string
	sliceOffset                    uint64
	sliceSize                      uint64
	layout                         machoLayout
	supfTable                      *supf
}

type ipaInventory struct {
	path        string
	bytes       int64
	sha256      string
	sinfMembers []string
	images      []encryptedImage
	supfTables  map[string]supf
	cachedFiles map[string][]byte
}

type DecryptOptions struct {
	InputPath, OutputPath, ReportPath, ModelPath string
	Force                                        bool
	// StripAccountData omits SC_Info license members and removes Apple ID
	// fields from iTunesMetadata.plist in the output.
	StripAccountData bool
}

type DecryptResult struct {
	OutputPath             string
	OutputSHA256           string
	ReportPath             string
	EncryptedImages        int
	DecryptedPages         int
	PlaintextVerified      bool
	LogicalKeySHA256       string
	LogicalKeySHA256BySINF map[string]string
	// Set by StripAccountData; the counts are zero when nothing was removed.
	AccountDataStripped   bool
	RemovedLicenseFiles   int
	RemovedMetadataFields int
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func zipBytes(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func adjacentSINF(member string) string {
	return path.Join(path.Dir(member), "SC_Info", path.Base(member)+".sinf")
}

func readMachOProbe(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	header, err := io.ReadAll(io.LimitReader(reader, 32))
	if err != nil {
		return nil, err
	}
	if len(header) < 4 {
		return header, nil
	}
	magic := binary.LittleEndian.Uint32(header[:4])
	if magic == mhMagic32 || magic == mhMagic64 {
		headerBytes := 28
		if magic == mhMagic64 {
			headerBytes = 32
		}
		if len(header) < headerBytes {
			return header, nil
		}
		commandsBytes := int(binary.LittleEndian.Uint32(header[20:24]))
		required := headerBytes + commandsBytes
		if required < headerBytes || required > 1024*1024 || uint64(required) > file.UncompressedSize64 {
			return header, fmt.Errorf("Mach-O load-command extent is invalid")
		}
		probe := make([]byte, required)
		copy(probe, header)
		if required > len(header) {
			if _, err := io.ReadFull(reader, probe[len(header):]); err != nil {
				return probe, err
			}
		}
		return probe, nil
	}
	if isFatMachO(header) {
		remainder, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		return append(header, remainder...), nil
	}
	return header, nil
}

func openIPAInventory(path string) (ipaInventory, *zip.ReadCloser, error) {
	var result ipaInventory
	abs, err := filepath.Abs(path)
	if err != nil {
		return result, nil, err
	}
	state, err := os.Stat(abs)
	if err != nil {
		return result, nil, err
	}
	result.path = abs
	result.bytes = state.Size()
	result.sha256, err = fileSHA256(abs)
	if err != nil {
		return result, nil, err
	}
	archive, err := zip.OpenReader(abs)
	if err != nil {
		return result, nil, err
	}
	result.supfTables = map[string]supf{}
	result.cachedFiles = map[string][]byte{}
	names := map[string]bool{}
	files := map[string]*zip.File{}
	for _, file := range archive.File {
		if previous, exists := files[file.Name]; exists {
			// Some App Store repacks repeat an empty directory marker. It has no
			// payload to choose between; duplicate files remain ambiguous.
			if strings.HasSuffix(file.Name, "/") && previous.FileInfo().IsDir() &&
				file.FileInfo().IsDir() && previous.UncompressedSize64 == 0 && file.UncompressedSize64 == 0 {
				continue
			}
			archive.Close()
			return result, nil, fmt.Errorf("duplicate IPA member %q", file.Name)
		}
		names[file.Name] = true
		files[file.Name] = file
		if strings.HasSuffix(file.Name, ".sinf") {
			result.sinfMembers = append(result.sinfMembers, file.Name)
		}
	}
	associations, err := buildSINFAssociations(files)
	if err != nil {
		archive.Close()
		return result, nil, err
	}
	for _, file := range archive.File {
		if file.FileInfo().IsDir() {
			continue
		}
		probe, err := readMachOProbe(file)
		if err != nil {
			archive.Close()
			return result, nil, fmt.Errorf("%s: %w", file.Name, err)
		}
		if len(probe) < 4 {
			continue
		}
		magic := binary.LittleEndian.Uint32(probe[:4])
		if magic != mhMagic32 && magic != mhMagic64 && !isFatMachO(probe) {
			if !isKnownUnsupportedMachO(probe) {
				continue
			}
			archive.Close()
			return result, nil, fmt.Errorf("%s: unsupported Mach-O format; cannot establish complete encryption inventory", file.Name)
		}
		slices, parseErr := parseMachOSlices(probe, file.UncompressedSize64)
		if parseErr != nil {
			archive.Close()
			return result, nil, fmt.Errorf("%s: %w", file.Name, parseErr)
		}
		var encrypted []machoSlice
		for _, slice := range slices {
			if slice.layout.cryptID != 0 {
				encrypted = append(encrypted, slice)
			}
		}
		if len(encrypted) == 0 {
			continue
		}
		if isFatMachO(probe) {
			result.cachedFiles[file.Name] = probe
		}
		supfMember, table, err := selectImageKeyTable(files, file.Name, slices)
		if err != nil {
			archive.Close()
			return result, nil, err
		}
		if err := table.ValidateUniversalSignatureBinding(probe, slices); err != nil {
			archive.Close()
			return result, nil, fmt.Errorf("%s: %w", file.Name, err)
		}
		targetSINF := adjacentSINF(file.Name)
		sinfMember := associations[targetSINF]
		if sinfMember == "" && names[targetSINF] {
			sinfMember = targetSINF
		}
		if sinfMember == "" {
			archive.Close()
			return result, nil, fmt.Errorf("encrypted Mach-O %q has no declared or adjacent SINF", file.Name)
		}
		result.supfTables[supfMember] = table
		for _, slice := range encrypted {
			records, err := table.recordsFor(slice.layout.cpuType, slice.layout.cpuSubtype)
			if err != nil {
				archive.Close()
				return result, nil, fmt.Errorf("%s: %w", file.Name, err)
			}
			if len(records) != int(slice.layout.cryptSize)/pageBytes {
				archive.Close()
				return result, nil, fmt.Errorf("%s: SUPF page count mismatch for architecture %#x/%#x", file.Name, slice.layout.cpuType, slice.layout.cpuSubtype)
			}
			result.images = append(result.images, encryptedImage{
				member: file.Name, supfMember: supfMember, sinfMember: sinfMember,
				sliceOffset: slice.offset, sliceSize: slice.size, layout: slice.layout, supfTable: &table,
			})
		}
	}
	if len(result.images) == 0 {
		archive.Close()
		return result, nil, fmt.Errorf("IPA contains no supported encrypted Mach-O images")
	}
	return result, archive, nil
}

func decryptPagesInPlace(output []byte, image encryptedImage, records [][32]byte, deriver *pageKeyDeriver) ([][16]byte, error) {
	start := int(image.layout.cryptOffset)
	end := start + int(image.layout.cryptSize)
	if start < 0 || end < start || end > len(output) || len(records)*pageBytes != int(image.layout.cryptSize) {
		return nil, fmt.Errorf("%s: encrypted page geometry changed", image.member)
	}
	keys := make([][16]byte, len(records))
	workers := min(runtime.GOMAXPROCS(0), len(records))
	if workers < 1 {
		workers = 1
	}
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func(first int) {
			defer group.Done()
			for index := first; index < len(records); index += workers {
				record := records[index]
				key := deriver.pageKey(
					record[:16], image.sliceOffset+uint64(image.layout.cryptOffset)+uint64(index*pageBytes),
				)
				keys[index] = key
				block, _ := aes.NewCipher(key[:])
				clear(key[:])
				pageStart := start + index*pageBytes
				page := output[pageStart : pageStart+pageBytes]
				cipher.NewCBCDecrypter(block, record[16:]).CryptBlocks(page, page)
			}
		}(worker)
	}
	group.Wait()
	return keys, nil
}

func decryptImage(output []byte, image encryptedImage, records [][32]byte, mask [16]byte, deriver *pageKeyDeriver) (*imageReport, error) {
	if image.layout.cryptID != 1 {
		return nil, fmt.Errorf("%s: expected cryptid 1", image.member)
	}
	start := int(image.layout.cryptOffset)
	end := start + int(image.layout.cryptSize)
	id := image.layout.cryptIDOffset
	if id < 0 || id+4 > start || start < 0 || end < start || end > len(output) {
		return nil, fmt.Errorf("%s: invalid FairPlay mutation ranges", image.member)
	}
	encryptedDigest := sha256.Sum256(output)
	prefixDigest := sha256.Sum256(output[:id])
	headerDigest := sha256.Sum256(output[id+4 : start])
	suffixDigest := sha256.Sum256(output[end:])
	if image.supfTable != nil {
		if err := image.supfTable.ValidateSignatureBinding(output, image.layout); err != nil {
			return nil, fmt.Errorf("%s: %w", image.member, err)
		}
	}
	audits, err := auditCodeDirectories(output, image.layout)
	if err != nil {
		return nil, err
	}
	for _, audit := range audits {
		if audit.MatchedSlots != audit.SlotCount {
			return nil, fmt.Errorf("%s: encrypted source fails CodeDirectory", image.member)
		}
	}
	keys, err := decryptPagesInPlace(output, image, records, deriver)
	if err != nil {
		return nil, err
	}
	keysHash := sha256.New()
	for _, key := range keys {
		keysHash.Write(key[:])
	}
	clear(keys)
	// Restore the unencrypted Mach-O header before checking any signature
	// page that may overlap both the header and encrypted region.
	binary.LittleEndian.PutUint32(output[id:id+4], 0)
	plaintextAudits, err := auditPreEncryptionCodeDirectories(output, image.layout)
	if err != nil {
		return nil, fmt.Errorf("%s: validate plaintext hashes: %w", image.member, err)
	}
	for _, audit := range plaintextAudits {
		if audit.MatchedSlots != audit.SlotCount {
			return nil, fmt.Errorf("%s: plaintext page hash mismatch (%d/%d)", image.member, audit.MatchedSlots, audit.SlotCount)
		}
	}
	if sha256.Sum256(output[:id]) != prefixDigest ||
		sha256.Sum256(output[id+4:start]) != headerDigest ||
		sha256.Sum256(output[end:]) != suffixDigest {
		return nil, fmt.Errorf("%s: mutation escaped FairPlay range", image.member)
	}
	validation := "code-directory-pre-encryption-hashes"
	if len(plaintextAudits) == 0 {
		validation = "unavailable-no-pre-encryption-hashes"
	}
	decryptedDigest := sha256.Sum256(output)
	report := &imageReport{
		Member: image.member, SUPFMember: image.supfMember,
		Architecture: machoArchitecture(image.layout.cpuType, image.layout.cpuSubtype), CPUType: image.layout.cpuType, CPUSubtype: image.layout.cpuSubtype,
		SliceOffset: image.sliceOffset, SliceSize: image.sliceSize,
		EncryptedSHA256: hex.EncodeToString(encryptedDigest[:]), DecryptedSHA256: hex.EncodeToString(decryptedDigest[:]),
		CryptOffset: image.layout.cryptOffset, CryptSize: image.layout.cryptSize, Pages: len(records),
		FirstPlaintextPageSHA256:     digest(output[start : start+pageBytes]),
		PlaintextValidation:          validation,
		PreEncryptionCodeDirectories: plaintextAudits,
		OrderedPageKeysSHA256:        hex.EncodeToString(keysHash.Sum(nil)), AppMaskSHA256: digest(mask[:]),
		CodeDirectories: audits, CryptIDBefore: 1, CryptIDAfter: 0, ExactMutationScope: true,
	}
	return report, nil
}

func validateInventoriedImages(blob []byte, images []encryptedImage) error {
	if len(images) == 0 {
		return fmt.Errorf("encrypted image inventory is empty")
	}
	slices, err := parseMachOSlices(blob, uint64(len(blob)))
	if err != nil {
		return err
	}
	encrypted := make([]machoSlice, 0, len(slices))
	for _, slice := range slices {
		if slice.layout.cryptID != 0 {
			encrypted = append(encrypted, slice)
		}
	}
	if len(encrypted) != len(images) {
		return fmt.Errorf("encrypted slice inventory changed")
	}
	for index, slice := range encrypted {
		image := images[index]
		if slice.offset != image.sliceOffset || slice.size != image.sliceSize || !sameMachoLayout(slice.layout, image.layout) {
			return fmt.Errorf("encrypted slice %d changed after inventory", index)
		}
	}
	return nil
}

func stagePrivateJSON(path string, value any) (string, error) {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".fairplay-*.json")
	if err != nil {
		return "", err
	}
	name := temporary.Name()
	complete := false
	defer func() {
		temporary.Close()
		if !complete {
			os.Remove(name)
		}
	}()
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	complete = true
	return name, nil
}

func DecryptIPA(options DecryptOptions) (DecryptResult, error) {
	var result DecryptResult
	if err := checkPlatform(); err != nil {
		return result, err
	}
	options, err := validatePaths(options)
	if err != nil {
		return result, err
	}
	for _, path := range []string{options.OutputPath, options.ReportPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return result, err
		}
	}
	inventory, source, err := openIPAInventory(options.InputPath)
	if err != nil {
		return result, err
	}
	defer source.Close()
	files := map[string]*zip.File{}
	for _, file := range source.File {
		files[file.Name] = file
	}
	licenses, licenseReports, err := resolveIPALicenses(inventory, files, options.ModelPath)
	if err != nil {
		return result, err
	}
	defer func() {
		for _, license := range licenses {
			clear(license.material.LogicalKey[:])
			clear(license.mask[:])
		}
	}()
	keyHashes := make(map[string]string, len(licenseReports))
	sharedKeyHash, providerName, modelName := "", "", ""
	for index, license := range licenseReports {
		keyHashes[license.Member] = license.LogicalKeySHA256
		if index == 0 {
			sharedKeyHash, providerName, modelName = license.LogicalKeySHA256, license.Provider, license.ModelBuild
			continue
		}
		if sharedKeyHash != license.LogicalKeySHA256 {
			sharedKeyHash = ""
		}
		if providerName != license.Provider {
			providerName = "multiple"
		}
		if modelName != license.ModelBuild {
			modelName = "multiple"
		}
	}
	oracle := map[string]any{"request_ipa_sha256": inventory.sha256}
	if len(licenseReports) == 1 {
		oracle = licenseReports[0].Oracle
	}
	imageMap := map[string][]encryptedImage{}
	for _, image := range inventory.images {
		imageMap[image.member] = append(imageMap[image.member], image)
	}
	temporary, err := os.CreateTemp(filepath.Dir(options.OutputPath), ".fairplay-*.ipa")
	if err != nil {
		return result, err
	}
	tempName := temporary.Name()
	defer os.Remove(tempName)
	defer temporary.Close()
	outputHasher := sha256.New()
	writer := zip.NewWriter(io.MultiWriter(temporary, outputHasher))
	var imageReports []*imageReport
	pages := 0
	var stripper *accountDataStripper
	if options.StripAccountData {
		stripper = &accountDataStripper{}
	}
	seenDirectories := map[string]bool{}
	for _, file := range source.File {
		if file.FileInfo().IsDir() {
			if seenDirectories[file.Name] {
				continue // Duplicate empty directory markers were checked during inventory.
			}
			seenDirectories[file.Name] = true
		}
		if stripper != nil {
			// Licenses were already resolved from the input above.
			handled, err := stripper.write(writer, file)
			if err != nil {
				return result, err
			}
			if handled {
				continue
			}
		}
		images, encrypted := imageMap[file.Name]
		if !encrypted {
			if err := writer.Copy(file); err != nil {
				return result, err
			}
			continue
		}
		blob, cached := inventory.cachedFiles[file.Name]
		if !cached {
			blob, err = zipBytes(file)
			if err != nil {
				return result, err
			}
		}
		if err := validateInventoriedImages(blob, images); err != nil {
			return result, fmt.Errorf("%s: %w", file.Name, err)
		}
		table, ok := inventory.supfTables[images[0].supfMember]
		if !ok {
			return result, fmt.Errorf("%s: inventoried SUPF is unavailable", file.Name)
		}
		header := file.FileHeader
		target, err := writer.CreateHeader(&header)
		if err != nil {
			return result, err
		}
		license := licenses[images[0].sinfMember]
		for _, image := range images {
			end := image.sliceOffset + image.sliceSize
			if end < image.sliceOffset || end > uint64(len(blob)) {
				return result, fmt.Errorf("%s slice changed after inventory", image.member)
			}
			records, err := table.recordsFor(image.layout.cpuType, image.layout.cpuSubtype)
			if err != nil {
				return result, err
			}
			report, err := decryptImage(blob[image.sliceOffset:end], image, records, license.mask, license.deriver)
			if err != nil {
				return result, err
			}
			report.SINFMember = image.sinfMember
			imageReports = append(imageReports, report)
			pages += len(records)
		}
		if _, err := target.Write(blob); err != nil {
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
	outputHash := hex.EncodeToString(outputHasher.Sum(nil))
	plaintextVerified := true
	for _, image := range imageReports {
		plaintextVerified = plaintextVerified && len(image.PreEncryptionCodeDirectories) > 0
	}
	report := decryptionReport{
		Schema: "unfairplay-decryption-v2", ModelBuild: modelName,
		Input:    reportFile{Path: inventory.path, Bytes: inventory.bytes, SHA256: inventory.sha256},
		Output:   reportFile{Path: options.OutputPath, SHA256: outputHash, Mode: "0600"},
		Provider: providerName, Oracle: oracle, Licenses: licenseReports,
		EncryptedImages: len(imageReports), DecryptedPages: pages, Images: imageReports,
		Complete:          len(imageReports) == len(inventory.images),
		PlaintextVerified: plaintextVerified,
		AccountData:       stripper.report(),
		Warnings: []string{
			"Available pre-encryption hashes matched every covered encrypted-range page; images without these hashes have no plaintext hash verification. Other code pages are not covered.",
			"Apple CMS code-signature trust and SUPF certificate signatures are not authenticated by IPA decryption.",
			"CodeDirectory checks compare encrypted bytes with embedded hashes, not an authenticated Apple signature; those hashes are stale after decryption.",
			"Analysis IPA requires recursive re-signing before installation.",
		},
	}
	reportTemp, err := stagePrivateJSON(options.ReportPath, report)
	if err != nil {
		return result, err
	}
	defer os.Remove(reportTemp)
	if _, err := validatePaths(options); err != nil {
		return result, err
	}
	if err := publishFiles([]stagedFile{{tempName, options.OutputPath}, {reportTemp, options.ReportPath}}, options.Force); err != nil {
		return result, err
	}
	result = DecryptResult{
		OutputPath: options.OutputPath, OutputSHA256: outputHash, ReportPath: options.ReportPath, PlaintextVerified: plaintextVerified,
		EncryptedImages: len(imageReports), DecryptedPages: pages,
		LogicalKeySHA256: sharedKeyHash, LogicalKeySHA256BySINF: keyHashes,
	}
	if account := stripper.report(); account != nil {
		result.AccountDataStripped = true
		result.RemovedLicenseFiles, result.RemovedMetadataFields = account.RemovedLicenseFiles, account.RemovedMetadataFields
	}
	return result, nil
}
