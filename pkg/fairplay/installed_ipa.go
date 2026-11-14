package fairplay

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// archiveInstalledApp preserves the complete inner iOS bundle byte-for-byte.
// The result is a validation archive, not a reconstruction of the Store IPA.
func archiveInstalledApp(app, destination string) (result EnrollmentCaptureFile, returnErr error) {
	resolvedApp, err := canonicalPath(app)
	if err != nil {
		return result, err
	}
	resolvedDestination, err := canonicalPath(destination)
	if err != nil {
		return result, err
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		resolvedApp, resolvedDestination = strings.ToLower(resolvedApp), strings.ToLower(resolvedDestination)
	}
	relativeDestination, err := filepath.Rel(resolvedApp, resolvedDestination)
	if err != nil {
		return result, err
	}
	if relativeDestination != ".." && !strings.HasPrefix(relativeDestination, ".."+string(filepath.Separator)) {
		return result, fmt.Errorf("validation archive destination must be outside the installed app")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return result, err
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return result, err
	}
	defer func() {
		_ = output.Close()
		if returnErr != nil {
			_ = os.Remove(destination)
		}
	}()
	writer := zip.NewWriter(output)
	seen := map[string]bool{}
	walkErr := filepath.WalkDir(app, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("installed bundle contains a symlink or special file")
		}
		if name == app {
			if !info.IsDir() {
				return fmt.Errorf("installed app must be a directory")
			}
			return nil
		}
		relative, err := filepath.Rel(app, name)
		if err != nil {
			return err
		}
		if strings.ContainsAny(relative, "\\:\x00") || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("installed bundle contains an unsafe member name")
		}
		member := "Payload/App.app/" + filepath.ToSlash(relative)
		folded := strings.ToLower(member)
		if seen[folded] {
			return fmt.Errorf("installed bundle contains case-colliding member names")
		}
		seen[folded] = true
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = member
		if info.IsDir() {
			header.Name += "/"
			_, err = writer.CreateHeader(header)
			return err
		}
		// Verify the opened file is the regular file observed by WalkDir, rather
		// than following a symlink substituted between inspection and opening.
		input, err := os.Open(name)
		if err != nil {
			return err
		}
		defer input.Close()
		opened, err := input.Stat()
		if err != nil {
			return err
		}
		if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
			return fmt.Errorf("installed bundle changed while archiving")
		}
		header.Method = zip.Deflate
		target, err := writer.CreateHeader(header)
		if err != nil {
			return err
		}
		copied, err := io.Copy(target, input)
		if err != nil {
			return err
		}
		after, err := input.Stat()
		if err != nil {
			return err
		}
		if copied != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
			return fmt.Errorf("installed bundle file changed while archiving")
		}
		return input.Close()
	})
	zipErr := writer.Close()
	syncErr := output.Sync()
	closeErr := output.Close()
	if err := errors.Join(walkErr, zipErr, syncErr, closeErr); err != nil {
		return result, err
	}
	digest, size, err := digestFile(destination)
	if err != nil {
		return result, err
	}
	return EnrollmentCaptureFile{Path: filepath.ToSlash(destination), Bytes: size, SHA256: digest, Mode: "0600"}, nil
}

func installedValidationIPA(app, destination string) (EnrollmentCaptureFile, error) {
	descriptor, err := archiveInstalledApp(app, destination)
	if err != nil {
		return descriptor, fmt.Errorf("cannot construct installed-app validation archive: %w; pass --ipa with a matching personalized IPA", err)
	}
	_, archive, err := openIPAInventory(destination)
	if archive != nil {
		_ = archive.Close()
	}
	if err != nil {
		_ = os.Remove(destination)
		return EnrollmentCaptureFile{}, fmt.Errorf("installed bundle cannot validate encrypted IPA decryption: %w; pass --ipa with a matching personalized IPA", err)
	}
	return descriptor, nil
}
