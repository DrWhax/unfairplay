package fairplay

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const maximumEnrollmentModels = 256

func privateModelPermissions(info os.FileInfo, kind string) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("FairPlay enrollment model %s must not be accessible by group or other users", kind)
	}
	return nil
}

func readEnrollmentModel(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect FairPlay enrollment model: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("FairPlay enrollment model is not a regular file")
	}
	if err := privateModelPermissions(info, "file"); err != nil {
		return nil, err
	}
	pack, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read FairPlay enrollment model: %w", err)
	}
	return pack, nil
}

func readEnrollmentModelRegistry(path string) ([][]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect FairPlay enrollment model registry: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("FairPlay enrollment model registry is not a directory")
	}
	if err := privateModelPermissions(info, "directory"); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("read FairPlay enrollment model registry: %w", err)
	}
	packs := make([][]byte, 0, len(entries))
	for _, entry := range entries {
		if !strings.EqualFold(filepath.Ext(entry.Name()), ".bin") {
			continue
		}
		if len(packs) == maximumEnrollmentModels {
			return nil, fmt.Errorf("FairPlay enrollment model registry contains more than %d models", maximumEnrollmentModels)
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("FairPlay enrollment model registry contains a symlink: %s", entry.Name())
		}
		pack, readErr := readEnrollmentModel(filepath.Join(path, entry.Name()))
		if readErr != nil {
			return nil, readErr
		}
		packs = append(packs, pack)
	}
	if len(packs) == 0 {
		return nil, fmt.Errorf("FairPlay enrollment model registry contains no .bin models")
	}
	return packs, nil
}

func clearModelPacks(packs [][]byte) {
	for _, pack := range packs {
		clear(pack)
	}
}
