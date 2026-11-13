package fairplay

import (
	"archive/zip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"howett.net/plist"
)

type MacOSAppOptions struct{ InputPath, OutputPath string }
type MacOSAppResult struct {
	OutputPath        string `json:"output_path"`
	ConvertedImages   int    `json:"converted_images"`
	SignatureVerified bool   `json:"signature_verified"`
	// Conversion and signing do not establish application runtime compatibility.
	RuntimeVerified bool `json:"runtime_verified"`
}

// ConvertDecryptedIPAToMacOS builds a locally signed Catalyst app on Apple
// silicon. It never opens the app or executes any code supplied by the IPA.
func ConvertDecryptedIPAToMacOS(ctx context.Context, options MacOSAppOptions) (MacOSAppResult, error) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return MacOSAppResult{}, fmt.Errorf("decrypted IPA conversion requires macOS on Apple silicon")
	}
	return convertDecryptedIPA(ctx, options, runMacOSCodesign)
}

type macOSSigner func(context.Context, ...string) error

func runMacOSCodesign(ctx context.Context, args ...string) error {
	output, err := exec.CommandContext(ctx, "/usr/bin/codesign", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("codesign: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func convertDecryptedIPA(ctx context.Context, options MacOSAppOptions, sign macOSSigner) (MacOSAppResult, error) {
	var result MacOSAppResult
	input, err := canonicalPath(options.InputPath)
	if err != nil {
		return result, err
	}
	if options.OutputPath == "" || !strings.EqualFold(filepath.Ext(options.OutputPath), ".app") {
		return result, fmt.Errorf("output must be a new .app directory")
	}
	output, err := canonicalPath(options.OutputPath)
	if err != nil {
		return result, err
	}
	// Never replace a directory tree or follow an output symlink.
	if _, err := os.Lstat(options.OutputPath); !os.IsNotExist(err) {
		return result, fmt.Errorf("output already exists or is inaccessible")
	}
	if pathsAlias(input, output) {
		return result, fmt.Errorf("input and output must be distinct")
	}
	archive, err := zip.OpenReader(input)
	if err != nil {
		return result, err
	}
	defer archive.Close()
	stage, err := os.MkdirTemp(filepath.Dir(output), ".unfairplay-macos-*")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(stage)
	app := filepath.Join(stage, filepath.Base(output))
	if err := os.Mkdir(app, 0o700); err != nil {
		return result, err
	}
	images, bundles, err := extractMacOSApp(ctx, archive, app)
	if err != nil {
		return result, err
	}
	entitlements, err := plist.Marshal(map[string]any{
		"com.apple.security.app-sandbox":                    true,
		"com.apple.security.network.client":                 true,
		"com.apple.security.files.user-selected.read-write": true,
	}, plist.XMLFormat)
	if err != nil {
		return result, err
	}
	entPath := filepath.Join(stage, "entitlements.plist")
	if err := os.WriteFile(entPath, entitlements, 0o600); err != nil {
		return result, err
	}
	for _, image := range images {
		if err := sign(ctx, "--force", "--sign", "-", "--timestamp=none", image); err != nil {
			return result, err
		}
	}
	// Sign nested bundles before their containing bundles, sealing each Info.plist.
	sort.Slice(bundles, func(i, j int) bool { return len(bundles[i]) > len(bundles[j]) })
	for _, bundle := range bundles {
		args := []string{"--force", "--sign", "-", "--timestamp=none"}
		if strings.EqualFold(filepath.Ext(bundle), ".app") || strings.EqualFold(filepath.Ext(bundle), ".appex") {
			args = append(args, "--entitlements", entPath)
		}
		if err := sign(ctx, append(args, bundle)...); err != nil {
			return result, err
		}
	}
	if err := sign(ctx, "--verify", "--deep", "--strict", app); err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	// Reserve the destination exclusively, then move the sealed contents.
	// Directory publication is not crash-atomic; ordinary failures remove it.
	if err := os.Mkdir(output, 0o700); err != nil {
		return result, err
	}
	entries, err := os.ReadDir(app)
	if err != nil {
		os.Remove(output)
		return result, err
	}
	for _, entry := range entries {
		if err := os.Rename(filepath.Join(app, entry.Name()), filepath.Join(output, entry.Name())); err != nil {
			os.RemoveAll(output)
			return result, err
		}
	}
	return MacOSAppResult{OutputPath: output, ConvertedImages: len(images), SignatureVerified: true}, nil
}

func macOSMemberName(name string) (string, error) {
	trimmed := strings.TrimSuffix(name, "/")
	if trimmed == "" || path.IsAbs(trimmed) || path.Clean(trimmed) != trimmed || strings.ContainsAny(trimmed, "\\:\x00") || trimmed == ".." || strings.HasPrefix(trimmed, "../") {
		return "", fmt.Errorf("unsafe IPA member %q", name)
	}
	return trimmed, nil
}

func extractMacOSApp(ctx context.Context, archive *zip.ReadCloser, destination string) ([]string, []string, error) {
	files := map[string]*zip.File{}
	folded := map[string]bool{}
	roots := map[string]bool{}
	for _, file := range archive.File {
		name, err := macOSMemberName(file.Name)
		if err != nil {
			return nil, nil, err
		}
		key := strings.ToLower(name)
		if folded[key] {
			return nil, nil, fmt.Errorf("duplicate or case-colliding IPA member %q", name)
		}
		folded[key] = true
		if file.Mode()&os.ModeSymlink != 0 || !file.Mode().IsRegular() && !file.FileInfo().IsDir() {
			return nil, nil, fmt.Errorf("IPA symlinks and special files are unsupported")
		}
		files[name] = file
		parts := strings.Split(name, "/")
		if len(parts) >= 2 && parts[0] == "Payload" && strings.HasSuffix(parts[1], ".app") {
			roots["Payload/"+parts[1]] = true
		}
	}
	if len(roots) != 1 {
		return nil, nil, fmt.Errorf("IPA must contain exactly one top-level Payload app")
	}
	var root string
	for name := range roots {
		root = name
	}
	infoFile := files[root+"/Info.plist"]
	if infoFile == nil {
		return nil, nil, fmt.Errorf("app has no Info.plist")
	}
	infoBytes, err := zipBytes(infoFile)
	if err != nil {
		return nil, nil, err
	}
	var info map[string]any
	if _, err := plist.Unmarshal(infoBytes, &info); err != nil {
		return nil, nil, fmt.Errorf("app Info.plist: %w", err)
	}
	executable, ok := info["CFBundleExecutable"].(string)
	if !ok || executable == "" || executable == "." || executable == ".." || strings.ContainsAny(executable, "/\\:\x00") {
		return nil, nil, fmt.Errorf("invalid CFBundleExecutable")
	}
	if id, ok := info["CFBundleIdentifier"].(string); !ok || strings.TrimSpace(id) == "" {
		return nil, nil, fmt.Errorf("missing CFBundleIdentifier")
	}
	images := []string{}
	bundles := []string{destination}
	mainFound := false
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if !strings.HasPrefix(name, root+"/") {
			continue
		}
		relative := strings.TrimPrefix(name, root+"/")
		// Store licenses, provisioning profiles and stale signatures do not apply
		// to the locally signed app. Watch apps cannot run on macOS.
		skip := false
		for _, component := range strings.Split(relative, "/") {
			if component == "SC_Info" || component == "_CodeSignature" || component == "Watch" || component == "embedded.mobileprovision" {
				skip = true
			}
		}
		if skip {
			continue
		}
		file := files[name]
		target := filepath.Join(destination, filepath.FromSlash(relative))
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return nil, nil, err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return nil, nil, err
		}
		if relative == "Info.plist" {
			delete(info, "LSRequiresIPhoneOS")
			delete(info, "MinimumOSVersion")
			info["CFBundleSupportedPlatforms"] = []string{"MacOSX"}
			info["LSMinimumSystemVersion"] = "11.0"
			data, err := plist.Marshal(info, plist.XMLFormat)
			if err != nil {
				return nil, nil, err
			}
			if err := writeMacOSBytes(target, data, 0o600); err != nil {
				return nil, nil, err
			}
			continue
		}
		// Probe before reading large resources into memory.
		probe, err := readMachOProbe(file)
		if err != nil {
			return nil, nil, err
		}
		macho := len(probe) >= 4 && (binary.LittleEndian.Uint32(probe[:4]) == mhMagic32 || binary.LittleEndian.Uint32(probe[:4]) == mhMagic64 || isFatMachO(probe) || isKnownUnsupportedMachO(probe))
		if macho {
			blob, err := zipBytes(file)
			if err != nil {
				return nil, nil, err
			}
			if relative == executable {
				slices, err := parseMachOSlices(blob, uint64(len(blob)))
				if err != nil {
					return nil, nil, err
				}
				for _, slice := range slices {
					if binary.LittleEndian.Uint32(blob[slice.offset+12:slice.offset+16]) != 2 {
						return nil, nil, fmt.Errorf("CFBundleExecutable is not MH_EXECUTE")
					}
				}
			}
			converted, err := convertDecryptedMachO(blob)
			if err != nil {
				return nil, nil, fmt.Errorf("convert %s: %w", relative, err)
			}
			if err := writeMacOSBytes(target, converted, 0o700); err != nil {
				return nil, nil, err
			}
			images = append(images, target)
			if relative == executable {
				mainFound = true
			}
		} else {
			if err := copyMacOSResource(file, target); err != nil {
				return nil, nil, err
			}
		}
		if path.Base(relative) == "Info.plist" {
			parent := filepath.Dir(target)
			for _, ext := range []string{".framework", ".appex", ".app", ".bundle", ".xpc"} {
				if strings.HasSuffix(parent, ext) {
					bundles = append(bundles, parent)
					break
				}
			}
		}
	}
	if !mainFound {
		return nil, nil, fmt.Errorf("CFBundleExecutable is missing or is not a supported Mach-O")
	}
	return images, bundles, nil
}

func copyMacOSResource(file *zip.File, target string) error {
	reader, err := file.Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, reader)
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func writeMacOSBytes(target string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}
