package fairplay

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func checkPlatform() error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return fmt.Errorf("FairPlay decryption is supported only on macOS and Linux; private-state permission validation is unavailable on %s", runtime.GOOS)
	}
	return nil
}

// canonicalPath resolves existing ancestors even when the final path is new.
func canonicalPath(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("FairPlay file path is empty")
	}
	abs, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	// A dangling symlink is not a new file and must not be treated as one.
	if info, statErr := os.Lstat(abs); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("dangling symlink: %s", abs)
	}
	parent := filepath.Dir(abs)
	if parent == abs {
		return "", err
	}
	resolved, err = canonicalPath(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, filepath.Base(abs)), nil
}

func pathsAlias(left, right string) bool {
	if left == right || (runtime.GOOS == "darwin" || runtime.GOOS == "windows") && strings.EqualFold(left, right) {
		return true
	}
	a, aErr := os.Stat(left)
	b, bErr := os.Stat(right)
	return aErr == nil && bErr == nil && os.SameFile(a, b)
}

func validatePaths(options DecryptOptions) (DecryptOptions, error) {
	inputs := []*string{&options.InputPath}
	for _, name := range inputs {
		resolved, err := canonicalPath(*name)
		if err != nil {
			return options, err
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return options, err
		}
		if !info.Mode().IsRegular() {
			return options, fmt.Errorf("FairPlay input must be a regular file: %s", resolved)
		}
		*name = resolved
	}
	if options.ModelPath != "" {
		resolved, err := canonicalPath(options.ModelPath)
		if err != nil {
			return options, err
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return options, err
		}
		if !info.Mode().IsRegular() && !info.IsDir() {
			return options, fmt.Errorf("FairPlay enrollment model must be a regular file or directory: %s", resolved)
		}
		options.ModelPath = resolved
		inputs = append(inputs, &options.ModelPath)
	}
	for _, name := range []*string{&options.OutputPath, &options.ReportPath} {
		info, err := os.Lstat(*name)
		if err != nil && !os.IsNotExist(err) {
			return options, err
		}
		if err == nil && !info.Mode().IsRegular() {
			return options, fmt.Errorf("FairPlay destination must be a regular file, not a symlink or directory: %s", *name)
		}
		resolved, err := canonicalPath(*name)
		if err != nil {
			return options, err
		}
		for _, input := range inputs {
			if pathsAlias(resolved, *input) {
				return options, fmt.Errorf("refusing to overwrite FairPlay input or private state: %s", resolved)
			}
		}
		if info != nil && !options.Force {
			return options, fmt.Errorf("refusing to replace %s", resolved)
		}
		*name = resolved
	}
	if pathsAlias(options.OutputPath, options.ReportPath) {
		return options, fmt.Errorf("FairPlay output and report paths must be distinct")
	}
	return options, nil
}

type stagedFile struct {
	temporary, destination string
}

type publishedFile struct {
	stagedFile
	info   os.FileInfo
	backup string
}

// publishFiles provides no-replace publication and rolls back ordinary I/O
// failures. Two separate directory entries cannot be committed crash-atomically.
// Destinations must reside in directories controlled by the caller.
func publishFiles(files []stagedFile, force bool) error {
	var published []publishedFile
	for _, file := range files {
		item := publishedFile{stagedFile: file}
		info, err := os.Stat(file.temporary)
		if err != nil {
			return errors.Join(err, rollbackFiles(published))
		}
		item.info = info
		if force {
			item.backup, err = backupDestination(file.destination)
			if err == nil {
				err = os.Rename(file.temporary, file.destination)
			}
		} else {
			// Link atomically fails if another writer created the destination.
			// Both names reside on the same filesystem by construction.
			err = os.Link(file.temporary, file.destination)
		}
		if err != nil {
			removeBackup(item.backup)
			return errors.Join(fmt.Errorf("publish %s: %w", file.destination, err), rollbackFiles(published))
		}
		published = append(published, item)
	}
	for _, item := range published {
		removeBackup(item.backup)
	}
	return nil
}

func backupDestination(name string) (string, error) {
	info, err := os.Lstat(name)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("refusing to replace non-regular destination %s", name)
	}
	directory, err := os.MkdirTemp(filepath.Dir(name), ".fairplay-backup-*")
	if err != nil {
		return "", err
	}
	backup := filepath.Join(directory, "previous")
	if err := os.Link(name, backup); err != nil {
		os.Remove(directory)
		return "", err
	}
	return backup, nil
}

func removeBackup(backup string) {
	if backup != "" {
		os.Remove(backup)
		os.Remove(filepath.Dir(backup))
	}
}

func rollbackFiles(files []publishedFile) error {
	var failures []error
	for index := len(files) - 1; index >= 0; index-- {
		item := files[index]
		info, err := os.Lstat(item.destination)
		if err == nil && !os.SameFile(info, item.info) {
			err = fmt.Errorf("destination changed during publication")
		} else if err == nil {
			if item.backup != "" {
				err = os.Rename(item.backup, item.destination)
			} else {
				err = os.Remove(item.destination)
			}
		} else if os.IsNotExist(err) {
			err = nil
			if item.backup != "" {
				err = os.Link(item.backup, item.destination)
			}
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("rollback %s (previous version retained at %q): %w", item.destination, item.backup, err))
		} else {
			removeBackup(item.backup)
		}
	}
	return errors.Join(failures...)
}
