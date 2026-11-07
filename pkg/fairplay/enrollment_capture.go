package fairplay

import (
	"archive/zip"
	"crypto/sha256"
	"debug/macho"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"howett.net/plist"
)

const (
	EnrollmentCaptureSchema                 = "unfairplay-native-enrollment-capture-v2"
	legacyUnfairPlayEnrollmentCaptureSchema = "unfairplay-native-enrollment-capture-v1"
	legacyEnrollmentCaptureSchema           = "ipatool-fairplay-native-enrollment-capture-v1"
)

type FairPlayBuildSupport struct {
	Profile         string `json:"profile"`
	Build           string `json:"build"`
	Status          string `json:"status"`
	ValidationBasis string `json:"validation_basis,omitempty"`
	Recovery        bool   `json:"recovery"`
	Decrypt         bool   `json:"end_to_end_decryption"`
}

// ResolveFairPlayBuildSupport validates an optional legacy daemon identity and
// always returns the same typed recovery contract. The daemon hash is
// provenance only; it never selects an algorithm.
func ResolveFairPlayBuildSupport(hash, build string) (FairPlayBuildSupport, bool) {
	if hash == "" {
		return FairPlayBuildSupport{
			Profile: "typed-current-enrollment", Build: build, Status: "portable-validation-required",
			ValidationBasis: "structural-enrollment-plus-complete-ipa-validation",
			Recovery:        true, Decrypt: false,
		}, false
	}
	normalized := strings.ToLower(hash)
	decoded, err := hex.DecodeString(normalized)
	if err != nil || len(decoded) != sha256.Size {
		return FairPlayBuildSupport{Build: build, Status: "invalid-fairplayd-identity"}, false
	}
	return FairPlayBuildSupport{
		Profile:         "typed-current-enrollment",
		Build:           build,
		Status:          "portable-validation-required",
		ValidationBasis: "structural-enrollment-plus-personalized-sinf-and-complete-ipa-validation",
		Recovery:        true,
		Decrypt:         false,
	}, false
}

type EnrollmentCaptureFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Mode   string `json:"mode"`
}

type EnrollmentCaptureApp struct {
	BundleIdentifier string       `json:"bundle_identifier"`
	Executable       string       `json:"executable"`
	ExecutablePath   string       `json:"executable_path,omitempty"`
	Selector         SINFSelector `json:"selector"`
	SelectorID       string       `json:"selector_id"`
	SINFPath         string       `json:"sinf_path"`
	TargetSINFPath   string       `json:"target_sinf_path,omitempty"`
	IPAMemberRoot    string       `json:"ipa_member_root,omitempty"`
}

type EnrollmentCaptureManifest struct {
	Schema         string                  `json:"schema"`
	CreatedAt      string                  `json:"created_at"`
	ProductVersion string                  `json:"product_version"`
	BuildVersion   string                  `json:"build_version"`
	FairPlayd      EnrollmentCaptureFile   `json:"fairplayd,omitzero"`
	FairPlay       FairPlayBuildSupport    `json:"enrollment_support"`
	HardwareMAC    EnrollmentCaptureFile   `json:"hardware_iomac"`
	App            EnrollmentCaptureApp    `json:"app"`
	IPA            *EnrollmentCaptureFile  `json:"ipa,omitempty"`
	Files          []EnrollmentCaptureFile `json:"files"`
	Warnings       []string                `json:"warnings,omitempty"`
}

type EnrollmentCollectOptions struct {
	AppPath                 string
	InstalledExecutablePath string
	IPAPath                 string
	OutputPath              string
	SystemStatePath         string
	SharedStatePath         string
	ADIPath                 string
	MACAddressPath          string
	HardwareInterface       string
	ProductVersion          string
	BuildVersion            string
}

type appInfo struct {
	BundleIdentifier string `plist:"CFBundleIdentifier"`
	Executable       string `plist:"CFBundleExecutable"`
}

func digestReader(reader io.Reader) (string, int64, error) {
	value := sha256.New()
	written, err := io.Copy(value, reader)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(value.Sum(nil)), written, nil
}

func digestFile(path string) (string, int64, error) {
	input, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer input.Close()
	return digestReader(input)
}

func createPrivateDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil {
		return fmt.Errorf("create private capture directory: %w", err)
	}
	return nil
}

func copyPrivateFile(source, destination string) (EnrollmentCaptureFile, error) {
	var result EnrollmentCaptureFile
	info, err := os.Lstat(source)
	if err != nil {
		return result, err
	}
	if !info.Mode().IsRegular() {
		return result, fmt.Errorf("capture source is not a regular file: %s", source)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return result, err
	}
	input, err := os.Open(source)
	if err != nil {
		return result, err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return result, err
	}
	value := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(output, value), input)
	closeErr := output.Close()
	if copyErr != nil {
		return result, copyErr
	}
	if closeErr != nil {
		return result, closeErr
	}
	return EnrollmentCaptureFile{
		Path: filepath.ToSlash(destination), Bytes: written,
		SHA256: hex.EncodeToString(value.Sum(nil)), Mode: "0600",
	}, nil
}

func writePrivateJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	output, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	encodeErr := encoder.Encode(value)
	closeErr := output.Close()
	if encodeErr != nil {
		return encodeErr
	}
	return closeErr
}

func relativeCaptureFile(root string, value EnrollmentCaptureFile) EnrollmentCaptureFile {
	relative, err := filepath.Rel(root, filepath.FromSlash(value.Path))
	if err == nil {
		value.Path = filepath.ToSlash(relative)
	}
	return value
}

func normalizeInstalledApp(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || !strings.EqualFold(filepath.Ext(path), ".app") {
		return "", fmt.Errorf("installed app path must name an .app directory")
	}
	wrapper := filepath.Join(path, "Wrapper")
	entries, err := os.ReadDir(wrapper)
	if errors.Is(err, os.ErrNotExist) {
		return path, nil
	}
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.EqualFold(filepath.Ext(entry.Name()), ".app") {
			return filepath.Join(wrapper, entry.Name()), nil
		}
	}
	return "", fmt.Errorf("outer app wrapper contains no inner .app")
}

func readAppInfo(app string) (appInfo, []byte, error) {
	var result appInfo
	data, err := os.ReadFile(filepath.Join(app, "Info.plist"))
	if err != nil {
		return result, nil, err
	}
	if _, err := plist.Unmarshal(data, &result); err != nil {
		return result, nil, fmt.Errorf("parse app Info.plist: %w", err)
	}
	if result.BundleIdentifier == "" || result.Executable == "" {
		return result, nil, fmt.Errorf("app Info.plist lacks bundle identifier or executable")
	}
	return result, data, nil
}

func selectAppSINF(app string) (string, SINFSelector, error) {
	directory := filepath.Join(app, "SC_Info")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return "", SINFSelector{}, err
	}
	var paths []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.EqualFold(filepath.Ext(entry.Name()), ".sinf") {
			paths = append(paths, filepath.Join(directory, entry.Name()))
		}
	}
	if len(paths) != 1 {
		return "", SINFSelector{}, fmt.Errorf("installed app must contain exactly one root SINF, found %d", len(paths))
	}
	data, err := os.ReadFile(paths[0])
	if err != nil {
		return "", SINFSelector{}, err
	}
	selector, err := ParseSINFSelector(data)
	return paths[0], selector, err
}

func copyDirectoryFiles(source, destination, captureRoot string) ([]EnrollmentCaptureFile, error) {
	info, err := os.Stat(source)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("capture state path is not a directory: %s", source)
	}
	var result []EnrollmentCaptureFile
	err = filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == source {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("capture state contains a symlink: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		copied, err := copyPrivateFile(path, filepath.Join(destination, relative))
		if err != nil {
			return err
		}
		result = append(result, relativeCaptureFile(captureRoot, copied))
		return nil
	})
	return result, err
}

func arm64eMachOHash(source string) (string, int64, error) {
	fat, err := macho.OpenFat(source)
	if err != nil {
		thin, thinErr := macho.Open(source)
		if thinErr != nil {
			return "", 0, fmt.Errorf("open fairplayd Mach-O: %w", err)
		}
		defer thin.Close()
		if thin.Cpu != macho.CpuArm64 || uint32(thin.SubCpu)&0x00ffffff != 2 {
			return "", 0, fmt.Errorf("fairplayd has no arm64e slice")
		}
		return digestFile(source)
	}
	defer fat.Close()
	var selected *macho.FatArch
	for index := range fat.Arches {
		arch := &fat.Arches[index]
		if arch.Cpu == macho.CpuArm64 && uint32(arch.SubCpu)&0x00ffffff == 2 {
			selected = arch
			if uint32(arch.SubCpu)&0xff000000 == 0 {
				break
			}
		}
	}
	if selected == nil {
		return "", 0, fmt.Errorf("fairplayd has no arm64e slice")
	}
	input, err := os.Open(source)
	if err != nil {
		return "", 0, err
	}
	defer input.Close()
	return digestReader(io.NewSectionReader(input, int64(selected.Offset), int64(selected.Size)))
}

func querySystemVersion(flag string) (string, error) {
	output, err := exec.Command("/usr/bin/sw_vers", flag).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func ioregHardwareMAC(interfaceName string) ([]byte, error) {
	// Unrelated registry properties can contain characters that are invalid in XML.
	output, err := exec.Command("/usr/sbin/ioreg", "-a", "-l", "-r", "-k", "IOMACAddress", "-p", "IOService").Output()
	if err != nil {
		return nil, fmt.Errorf("read IORegistry: %w", err)
	}
	return parseIORegistryHardwareMAC(output, interfaceName)
}

func parseIORegistryHardwareMAC(output []byte, interfaceName string) ([]byte, error) {
	var document any
	if _, err := plist.Unmarshal(output, &document); err != nil {
		return nil, fmt.Errorf("parse IORegistry: %w", err)
	}
	var roots []map[string]any
	switch value := document.(type) {
	case map[string]any:
		roots = append(roots, value)
	case []any:
		for _, entry := range value {
			// Skip a malformed unrelated subtree; a valid built-in interface
			// may still appear in another result from the filtered query.
			if root, ok := entry.(map[string]any); ok {
				roots = append(roots, root)
			}
		}
	default:
		return nil, fmt.Errorf("parse IORegistry: expected a dictionary or array of subtrees")
	}
	var visit func(map[string]any, map[string]any) []byte
	visit = func(node, parent map[string]any) []byte {
		name, _ := node["BSD Name"].(string)
		builtin, _ := node["IOBuiltin"].(bool)
		if name == interfaceName && builtin {
			if value, ok := parent["IOMACAddress"].([]byte); ok && len(value) == 6 {
				return append([]byte(nil), value...)
			}
		}
		children, _ := node["IORegistryEntryChildren"].([]any)
		for _, child := range children {
			if childMap, ok := child.(map[string]any); ok {
				if result := visit(childMap, node); result != nil {
					return result
				}
			}
		}
		return nil
	}
	for _, root := range roots {
		if result := visit(root, nil); result != nil {
			return result, nil
		}
	}
	return nil, fmt.Errorf("built-in interface %s has no six-byte parent IOMACAddress", interfaceName)
}

func writePrivateBytes(path string, data []byte) (EnrollmentCaptureFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return EnrollmentCaptureFile{}, err
	}
	output, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return EnrollmentCaptureFile{}, err
	}
	_, writeErr := output.Write(data)
	closeErr := output.Close()
	if writeErr != nil {
		return EnrollmentCaptureFile{}, writeErr
	}
	if closeErr != nil {
		return EnrollmentCaptureFile{}, closeErr
	}
	digest := sha256.Sum256(data)
	return EnrollmentCaptureFile{Path: filepath.ToSlash(path), Bytes: int64(len(data)), SHA256: hex.EncodeToString(digest[:]), Mode: "0600"}, nil
}

func ipaRootForSelector(path string, selector SINFSelector) (string, error) {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return "", err
	}
	defer archive.Close()
	var roots []string
	for _, file := range archive.File {
		if !strings.Contains(file.Name, "/SC_Info/") || !strings.HasSuffix(strings.ToLower(file.Name), ".sinf") {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			return "", err
		}
		data, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil {
			return "", readErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		found, parseErr := ParseSINFSelector(data)
		if parseErr == nil && found == selector {
			roots = append(roots, strings.Split(file.Name, "/SC_Info/")[0])
		}
	}
	if len(roots) == 0 {
		return "", fmt.Errorf("IPA contains no SINF matching selector %s", selector.Identifier())
	}
	sort.Slice(roots, func(left, right int) bool { return len(roots[left]) < len(roots[right]) })
	return roots[0], nil
}

func readIPAMember(path, member string) ([]byte, error) {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer archive.Close()
	for _, file := range archive.File {
		if file.Name != member {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		return data, nil
	}
	return nil, fmt.Errorf("IPA member not found: %s", member)
}

func CollectEnrollment(options EnrollmentCollectOptions) (EnrollmentCaptureManifest, error) {
	var manifest EnrollmentCaptureManifest
	if options.OutputPath == "" || options.AppPath == "" {
		return manifest, fmt.Errorf("capture requires app and output paths")
	}
	if runtime.GOOS != "darwin" && (options.ProductVersion == "" || options.BuildVersion == "" || options.MACAddressPath == "") {
		return manifest, fmt.Errorf("native enrollment collection requires macOS")
	}
	app, err := normalizeInstalledApp(options.AppPath)
	if err != nil {
		return manifest, err
	}
	metadata, infoData, err := readAppInfo(app)
	if err != nil {
		return manifest, err
	}
	sinfPath, selector, err := selectAppSINF(app)
	if err != nil {
		return manifest, err
	}
	if options.SystemStatePath == "" {
		options.SystemStatePath = "/private/var/db/fpsd/SC Info"
	}
	if options.SharedStatePath == "" {
		options.SharedStatePath = "/Users/Shared/SC Info"
	}
	if options.ADIPath == "" {
		options.ADIPath = "/private/var/db/fpsd/adi"
	}
	if options.HardwareInterface == "" {
		options.HardwareInterface = "en0"
	}
	if options.ProductVersion == "" {
		options.ProductVersion, err = querySystemVersion("-productVersion")
		if err != nil {
			return manifest, err
		}
	}
	if options.BuildVersion == "" {
		options.BuildVersion, err = querySystemVersion("-buildVersion")
		if err != nil {
			return manifest, err
		}
	}
	if err := createPrivateDirectory(options.OutputPath); err != nil {
		return manifest, err
	}

	var files []EnrollmentCaptureFile
	support, _ := ResolveFairPlayBuildSupport("", options.BuildVersion)

	var mac []byte
	if options.MACAddressPath != "" {
		mac, err = os.ReadFile(options.MACAddressPath)
		if err == nil && len(mac) != 6 {
			text := strings.NewReplacer(":", "", "-", "", "\n", "", "\r", "", " ", "").Replace(string(mac))
			mac, err = hex.DecodeString(text)
		}
	} else {
		mac, err = ioregHardwareMAC(options.HardwareInterface)
	}
	if err != nil || len(mac) != 6 {
		return manifest, fmt.Errorf("capture hardware IOMACAddress: %w", err)
	}
	hardware, err := writePrivateBytes(filepath.Join(options.OutputPath, "hardware", "iomac.bin"), mac)
	clear(mac)
	if err != nil {
		return manifest, err
	}
	hardware = relativeCaptureFile(options.OutputPath, hardware)
	files = append(files, hardware)

	infoFile, err := writePrivateBytes(filepath.Join(options.OutputPath, "app", "Info.plist"), infoData)
	if err != nil {
		return manifest, err
	}
	files = append(files, relativeCaptureFile(options.OutputPath, infoFile))
	executable, err := copyPrivateFile(filepath.Join(app, metadata.Executable), filepath.Join(options.OutputPath, "app", "executable"))
	if err != nil {
		return manifest, err
	}
	files = append(files, relativeCaptureFile(options.OutputPath, executable))
	licenseFiles, err := copyDirectoryFiles(filepath.Join(app, "SC_Info"), filepath.Join(options.OutputPath, "app", "SC_Info"), options.OutputPath)
	if err != nil {
		return manifest, err
	}
	files = append(files, licenseFiles...)

	for _, item := range []struct{ source, destination string }{
		{options.SystemStatePath, filepath.Join(options.OutputPath, "state", "fpsd-sc-info")},
		{options.SharedStatePath, filepath.Join(options.OutputPath, "state", "shared-sc-info")},
		{options.ADIPath, filepath.Join(options.OutputPath, "state", "adi")},
	} {
		captured, err := copyDirectoryFiles(item.source, item.destination, options.OutputPath)
		if err != nil {
			return manifest, fmt.Errorf("capture state %s: %w", item.source, err)
		}
		files = append(files, captured...)
	}
	if len(files) == 3+len(licenseFiles) {
		return manifest, fmt.Errorf("capture found no native FairPlay state files")
	}

	var ipaFile *EnrollmentCaptureFile
	ipaRoot := ""
	targetSINFPath := ""
	if options.IPAPath != "" {
		copied, err := copyPrivateFile(options.IPAPath, filepath.Join(options.OutputPath, "ipa", "App.ipa"))
		if err != nil {
			return manifest, err
		}
		copied = relativeCaptureFile(options.OutputPath, copied)
		files = append(files, copied)
		ipaFile = &copied
		ipaRoot, err = ipaRootForSelector(options.IPAPath, selector)
		if err != nil {
			return manifest, err
		}
		targetMember := ipaRoot + "/SC_Info/" + metadata.Executable + ".sinf"
		targetSINF, err := readIPAMember(options.IPAPath, targetMember)
		if err != nil {
			return manifest, err
		}
		targetSelector, parseErr := ParseSINFSelector(targetSINF)
		if parseErr != nil || targetSelector != selector {
			clear(targetSINF)
			return manifest, fmt.Errorf("IPA target SINF selector mismatch")
		}
		targetFile, err := writePrivateBytes(filepath.Join(options.OutputPath, "ipa", "App.sinf"), targetSINF)
		clear(targetSINF)
		if err != nil {
			return manifest, err
		}
		targetFile = relativeCaptureFile(options.OutputPath, targetFile)
		files = append(files, targetFile)
		targetSINFPath = targetFile.Path
	}

	installedExecutablePath := options.InstalledExecutablePath
	if installedExecutablePath == "" {
		installedExecutablePath = filepath.Join(app, metadata.Executable)
	} else if !filepath.IsAbs(installedExecutablePath) || filepath.Base(installedExecutablePath) != metadata.Executable {
		return EnrollmentCaptureManifest{}, fmt.Errorf("installed executable path must be absolute and end in %s", metadata.Executable)
	}
	manifest = EnrollmentCaptureManifest{
		Schema: EnrollmentCaptureSchema, CreatedAt: time.Now().UTC().Format(time.RFC3339),
		ProductVersion: options.ProductVersion, BuildVersion: options.BuildVersion,
		FairPlay: support, HardwareMAC: hardware,
		App: EnrollmentCaptureApp{
			BundleIdentifier: metadata.BundleIdentifier, Executable: metadata.Executable,
			ExecutablePath: installedExecutablePath,
			Selector:       selector, SelectorID: selector.Identifier(),
			SINFPath:       filepath.ToSlash(filepath.Join("app", "SC_Info", filepath.Base(sinfPath))),
			TargetSINFPath: targetSINFPath,
			IPAMemberRoot:  ipaRoot,
		},
		IPA: ipaFile, Files: files,
	}
	if ipaFile == nil {
		manifest.Warnings = append(manifest.Warnings, "capture has no IPA; recovery requires a matching personalized IPA")
	}
	if err := writePrivateJSON(filepath.Join(options.OutputPath, "manifest.json"), manifest); err != nil {
		return EnrollmentCaptureManifest{}, err
	}
	if err := restoreSudoOwnership(options.OutputPath); err != nil {
		return EnrollmentCaptureManifest{}, err
	}
	return manifest, nil
}

func restoreSudoOwnership(path string) error {
	uidText, gidText := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
	if os.Geteuid() != 0 || uidText == "" || gidText == "" {
		return nil
	}
	uid, uidErr := strconv.Atoi(uidText)
	gid, gidErr := strconv.Atoi(gidText)
	if uidErr != nil || gidErr != nil || uid < 0 || gid < 0 {
		return fmt.Errorf("invalid SUDO_UID/SUDO_GID")
	}
	return filepath.WalkDir(path, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to change ownership through symlink: %s", current)
		}
		return os.Chown(current, uid, gid)
	})
}

func LoadEnrollmentCapture(path string, verify bool) (EnrollmentCaptureManifest, error) {
	var manifest EnrollmentCaptureManifest
	info, err := os.Stat(path)
	if err != nil {
		return manifest, err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return manifest, fmt.Errorf("enrollment capture directory must be private (mode 0700 or stricter)")
	}
	data, err := os.ReadFile(filepath.Join(path, "manifest.json"))
	if err != nil {
		return manifest, err
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, err
	}
	if manifest.Schema != EnrollmentCaptureSchema && manifest.Schema != legacyUnfairPlayEnrollmentCaptureSchema && manifest.Schema != legacyEnrollmentCaptureSchema {
		return manifest, fmt.Errorf("unsupported enrollment capture schema %q", manifest.Schema)
	}
	if manifest.FairPlayd.SHA256 == "" {
		manifest.FairPlay, _ = ResolveFairPlayBuildSupport("", manifest.BuildVersion)
	} else {
		support, _ := ResolveFairPlayBuildSupport(manifest.FairPlayd.SHA256, manifest.BuildVersion)
		manifest.FairPlay = support
	}
	if !verify {
		return manifest, nil
	}
	for _, file := range manifest.Files {
		full, err := captureFilePath(path, file.Path)
		if err != nil {
			return manifest, err
		}
		info, err := os.Lstat(full)
		if err != nil {
			return manifest, err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return manifest, fmt.Errorf("capture file is not private and regular: %s", file.Path)
		}
		hash, size, err := digestFile(full)
		if err != nil {
			return manifest, err
		}
		if hash != file.SHA256 || size != file.Bytes {
			return manifest, fmt.Errorf("capture file changed: %s", file.Path)
		}
	}
	return manifest, nil
}

func captureFilePath(root, relative string) (string, error) {
	converted := filepath.FromSlash(relative)
	clean := filepath.Clean(converted)
	if relative == "" || filepath.IsAbs(converted) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("capture contains an unsafe relative path: %q", relative)
	}
	return filepath.Join(root, clean), nil
}
