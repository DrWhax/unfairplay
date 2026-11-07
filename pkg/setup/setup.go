// Package setup recovers a native Mac FairPlay enrollment and saves it as a
// reusable model for decrypting personalized IPAs.
package setup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/DrWhax/unfairplay/pkg/fairplay"
)

// Options configures Run. ModelDirectory is required.
type Options struct {
	AppPath, IPAPath, ModelDirectory, HardwareInterface string
	KeepWork                                            bool
	// Progress, when set, receives one status line per recovery step.
	Progress func(string)
}

func createPrivateModelDirectory(path string) ([]string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	var created []string
	for current := absolute; ; current = filepath.Dir(current) {
		info, statErr := os.Lstat(current)
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return nil, fmt.Errorf("model directory path is not a private directory: %s", current)
			}
			break
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return nil, statErr
		}
		created = append(created, current)
		parent := filepath.Dir(current)
		if parent == current {
			return nil, fmt.Errorf("model directory has no existing ancestor")
		}
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(absolute, 0o700); err != nil {
		return nil, err
	}
	return created, nil
}

func restoreInvokingUserOwnership(paths ...string) error {
	if os.Geteuid() != 0 || os.Getenv("SUDO_UID") == "" || os.Getenv("SUDO_GID") == "" {
		return nil
	}
	uid, uidErr := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, gidErr := strconv.Atoi(os.Getenv("SUDO_GID"))
	if uidErr != nil || gidErr != nil || uid < 0 || gid < 0 {
		return fmt.Errorf("invalid SUDO_UID/SUDO_GID")
	}
	for _, path := range paths {
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func restoreInvokingUserTree(path string) error {
	if os.Geteuid() != 0 || os.Getenv("SUDO_UID") == "" || os.Getenv("SUDO_GID") == "" {
		return nil
	}
	uid, uidErr := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, gidErr := strconv.Atoi(os.Getenv("SUDO_GID"))
	if uidErr != nil || gidErr != nil || uid < 0 || gid < 0 {
		return fmt.Errorf("invalid SUDO_UID/SUDO_GID")
	}
	return filepath.WalkDir(path, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("private setup state contains a symlink: %s", current)
		}
		return os.Chown(current, uid, gid)
	})
}

func installEnrollmentModel(directory, selector string, model []byte) (string, string, bool, error) {
	parts := strings.Split(selector, ":")
	if len(parts) != 2 || len(parts[0]) != 8 || len(parts[1]) != 8 {
		return "", "", false, fmt.Errorf("invalid enrollment selector %q", selector)
	}
	for _, part := range parts {
		if decoded, err := hex.DecodeString(part); err != nil || len(decoded) != 4 {
			return "", "", false, fmt.Errorf("invalid enrollment selector %q", selector)
		}
	}
	var err error
	directory, err = filepath.Abs(directory)
	if err != nil {
		return "", "", false, err
	}
	created, err := createPrivateModelDirectory(directory)
	if err != nil {
		return "", "", false, err
	}
	digest := sha256.Sum256(model)
	digestText := hex.EncodeToString(digest[:])
	name := strings.ReplaceAll(selector, ":", "-") + "-" + digestText + ".bin"
	path := filepath.Join(directory, name)
	reused := false
	if existing, readErr := os.ReadFile(path); readErr == nil {
		reused = bytes.Equal(existing, model)
		clear(existing)
		if !reused {
			return "", "", false, fmt.Errorf("saved model digest collision at %s", path)
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", "", false, readErr
	} else if err := writePrivateFile(path, model); err != nil {
		return "", "", false, err
	}
	ownership := append(created, directory, path)
	if err := restoreInvokingUserOwnership(ownership...); err != nil {
		return "", "", false, err
	}
	return path, digestText, reused, nil
}

// Run recovers the enrollment of one installed app and saves it under
// options.ModelDirectory.
func Run(ctx context.Context, options Options) (Result, error) {
	if options.ModelDirectory == "" {
		return Result{}, errors.New("setup: Options.ModelDirectory is required")
	}
	work, err := os.MkdirTemp("", "unfairplay-setup-*")
	if err != nil {
		return Result{}, err
	}
	if err := os.Chmod(work, 0o700); err != nil {
		return Result{}, err
	}
	cleaned := false
	if !options.KeepWork {
		defer func() {
			if !cleaned {
				_ = os.RemoveAll(work)
			}
		}()
	} else {
		defer func() { _ = restoreInvokingUserTree(work) }()
	}
	capture := filepath.Join(work, "capture")
	manifest, err := fairplay.CollectEnrollment(fairplay.EnrollmentCollectOptions{
		AppPath: options.AppPath, IPAPath: options.IPAPath, OutputPath: capture,
		HardwareInterface: options.HardwareInterface,
	})
	if err != nil {
		return Result{}, err
	}
	recoveryDirectory := filepath.Join(work, "recovery")
	recovered, err := Recover(ctx, RecoverOptions{
		Capture: capture, Output: recoveryDirectory, Progress: options.Progress,
	})
	if err != nil {
		return Result{}, err
	}
	model, err := os.ReadFile(recovered.ModelPath)
	if err != nil {
		return Result{}, err
	}
	defer clear(model)
	modelPath, modelSHA256, reused, err := installEnrollmentModel(options.ModelDirectory, manifest.App.SelectorID, model)
	if err != nil {
		return Result{}, err
	}
	if !options.KeepWork {
		if err := os.RemoveAll(work); err != nil {
			return Result{}, fmt.Errorf("remove temporary setup state: %w", err)
		}
		cleaned = true
	} else if err := restoreInvokingUserTree(work); err != nil {
		return Result{}, err
	}
	summary := setupSummary(recovered.Summary)
	summary["selector"] = manifest.App.SelectorID
	summary["model"] = modelPath
	summary["model_directory"] = options.ModelDirectory
	summary["model_sha256"] = modelSHA256
	summary["model_reused"] = reused
	if options.KeepWork {
		summary["work_directory"] = work
	}
	return Result{Summary: summary, ModelPath: modelPath}, nil
}

func setupSummary(recovered map[string]any) map[string]any {
	return map[string]any{
		"schema": "unfairplay-setup-v1", "success": true,
		"decrypted_ipa_sha256": recovered["decrypted_ipa_sha256"],
		"encrypted_images":     recovered["encrypted_images"], "decrypted_pages": recovered["decrypted_pages"],
		"plaintext_verified": recovered["plaintext_verified"],
		"warning":            "The saved enrollment model is private and can decrypt personalized IPAs for this enrollment.",
	}
}
