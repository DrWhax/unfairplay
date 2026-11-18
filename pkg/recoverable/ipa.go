// Package recoverable creates and restores application-key recovery IPAs.
package recoverable

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Options struct{ InputPath, OutputPath, ModelPath string }
type Result struct {
	Success           bool   `json:"success"`
	Output            string `json:"output"`
	PlaintextVerified bool   `json:"plaintext_verified"`
}

// SelectModel requires an explicit, unique destination model. Ambiguity never
// causes attempts against multiple accounts.
func SelectModel(path string) (string, error) {
	info, e := os.Stat(path)
	if e != nil {
		return "", e
	}
	if !info.IsDir() {
		return path, nil
	}
	if info.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("model directory must be private")
	}
	entries, e := os.ReadDir(path)
	if e != nil {
		return "", e
	}
	var selected string
	for _, v := range entries {
		if !strings.EqualFold(filepath.Ext(v.Name()), ".bin") {
			continue
		}
		if v.Type()&os.ModeSymlink != 0 || v.IsDir() {
			return "", fmt.Errorf("invalid model entry")
		}
		if selected != "" {
			return "", fmt.Errorf("multiple saved models: select one with --model")
		}
		selected = filepath.Join(path, v.Name())
	}
	if selected == "" {
		return "", fmt.Errorf("no saved models")
	}
	return selected, nil
}
func run(o Options, encrypt bool) (Result, error) {
	var result Result
	if !strings.EqualFold(filepath.Ext(o.InputPath), ".ipa") {
		return result, fmt.Errorf("input must be an IPA")
	}
	if o.OutputPath == "" {
		return result, fmt.Errorf("output is required")
	}
	if _, e := os.Lstat(o.OutputPath); !os.IsNotExist(e) {
		return result, fmt.Errorf("output must be a new file")
	}
	mp, e := SelectModel(o.ModelPath)
	if e != nil {
		return result, e
	}
	tmp, e := os.MkdirTemp(filepath.Dir(o.OutputPath), ".recoverable-")
	if e != nil {
		return result, e
	}
	defer os.RemoveAll(tmp)
	candidate := filepath.Join(tmp, "enhanced.ipa")
	if encrypt {
		e = encryptInto(o.InputPath, mp, tmp)
		candidate = filepath.Join(tmp, "restored.ipa")
	} else {
		e = pack(o.InputPath, mp, candidate)
	}
	if e != nil {
		return result, e
	}
	// Linking publishes without overwriting a destination created concurrently.
	if e = os.Link(candidate, o.OutputPath); e != nil {
		return result, e
	}
	return Result{true, o.OutputPath, true}, nil
}
func Decrypt(o Options) (Result, error) { return run(o, false) }
func Encrypt(o Options) (Result, error) { return run(o, true) }
