package fairplay

import (
	"archive/zip"
	"fmt"
	"io"
	"strings"

	"howett.net/plist"
)

// Account data that an output IPA does not need once its images are
// decrypted. SC_Info holds the personalized SINF/SUPF licenses, which
// identify the Store account. iTunesMetadata.plist carries the Apple ID
// written by downloaders and the purchaser record from the App Store.
var storeMetadataAccountKeys = []string{
	"apple-id", "appleId", "AppleID", "userName", "UserName",
	"purchaserID", "DSPersonID", "dsPersonId", "AltDSID", "altDsid", "FamilyID", "familyId",
}

const (
	storeMetadataMember   = "iTunesMetadata.plist"
	maxStoreMetadataBytes = 16 << 20
)

// accountDataStripper drops account data while an output archive is
// written. Licenses must already have been resolved from the input.
type accountDataStripper struct {
	removedLicenseFiles, removedMetadataFields int
}

// write handles file if it carries account data and reports whether it
// did; other members are left to the caller.
func (s *accountDataStripper) write(writer *zip.Writer, file *zip.File) (bool, error) {
	if isLicenseMember(file.Name) {
		if !file.FileInfo().IsDir() {
			s.removedLicenseFiles++
		}
		return true, nil
	}
	if file.Name != storeMetadataMember {
		return false, nil
	}
	data, removed, err := scrubStoreMetadata(file)
	if err != nil {
		return false, err
	}
	header := file.FileHeader
	header.Method = zip.Deflate
	target, err := writer.CreateHeader(&header)
	if err != nil {
		return false, err
	}
	if _, err := target.Write(data); err != nil {
		return false, err
	}
	s.removedMetadataFields += removed
	return true, nil
}

// accountDataReport is the report section written when stripping was
// requested. Counts are explicit even when nothing was removed.
type accountDataReport struct {
	Stripped              bool `json:"stripped"`
	RemovedLicenseFiles   int  `json:"removed_license_files"`
	RemovedMetadataFields int  `json:"removed_metadata_fields"`
}

func (s *accountDataStripper) report() *accountDataReport {
	if s == nil {
		return nil
	}
	return &accountDataReport{Stripped: true, RemovedLicenseFiles: s.removedLicenseFiles, RemovedMetadataFields: s.removedMetadataFields}
}

// isLicenseMember reports whether an archive member is inside any SC_Info
// directory: the app's, an extension's, a watch app's, or a framework's.
func isLicenseMember(name string) bool {
	for _, part := range strings.Split(strings.TrimSuffix(name, "/"), "/") {
		if strings.EqualFold(part, "SC_Info") {
			return true
		}
	}
	return false
}

// scrubStoreMetadata returns iTunesMetadata.plist without account fields,
// in its original plist format, and how many fields were removed.
func scrubStoreMetadata(file *zip.File) ([]byte, int, error) {
	tooLarge := fmt.Errorf("%s exceeds the %d-byte metadata limit", storeMetadataMember, maxStoreMetadataBytes)
	if file.UncompressedSize64 > maxStoreMetadataBytes {
		return nil, 0, tooLarge
	}
	reader, err := file.Open()
	if err != nil {
		return nil, 0, err
	}
	// archive/zip already rejects reads past the declared size; the bounded
	// read keeps memory use capped regardless.
	data, err := io.ReadAll(io.LimitReader(reader, maxStoreMetadataBytes+1))
	reader.Close()
	if err != nil {
		return nil, 0, err
	}
	if len(data) > maxStoreMetadataBytes {
		return nil, 0, tooLarge
	}
	var metadata map[string]any
	format, err := plist.Unmarshal(data, &metadata)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", storeMetadataMember, err)
	}
	removed := 0
	for _, key := range storeMetadataAccountKeys {
		if _, ok := metadata[key]; ok {
			delete(metadata, key)
			removed++
		}
	}
	if download, ok := metadata["com.apple.iTunesStore.downloadInfo"].(map[string]any); ok {
		if _, ok := download["accountInfo"]; ok {
			delete(download, "accountInfo")
			removed++
		}
	}
	data, err = plist.Marshal(metadata, format)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", storeMetadataMember, err)
	}
	return data, removed, nil
}
