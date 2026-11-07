package fairplay

import (
	"archive/zip"
	"bytes"
	"fmt"
	"path"
	"sort"
	"strings"

	"howett.net/plist"
)

type manifestSINFSource struct {
	name string
	data []byte
	file *zip.File
}

func clearManifestSINFSources(sources []manifestSINFSource) {
	for i := range sources {
		clear(sources[i].data)
	}
}

func loadManifestSINFSources(files map[string]*zip.File, root, manifestName string, relatives []string) ([]manifestSINFSource, error) {
	if len(relatives) == 0 {
		return nil, fmt.Errorf("manifest %q has no source SINF", manifestName)
	}
	sources := make([]manifestSINFSource, 0, len(relatives))
	seen := make(map[string]bool, len(relatives))
	for _, relative := range relatives {
		name, err := macOSSINFMember(root, relative)
		if err != nil {
			clearManifestSINFSources(sources)
			return nil, fmt.Errorf("manifest %q: %w", manifestName, err)
		}
		if seen[name] {
			clearManifestSINFSources(sources)
			return nil, fmt.Errorf("manifest %q has duplicate source SINF %q", manifestName, name)
		}
		seen[name] = true
		file := files[name]
		if file == nil {
			clearManifestSINFSources(sources)
			return nil, fmt.Errorf("manifest %q source SINF %q is missing", manifestName, name)
		}
		data, err := zipBytes(file)
		if err != nil {
			clearManifestSINFSources(sources)
			return nil, fmt.Errorf("read source SINF %q: %w", name, err)
		}
		sources = append(sources, manifestSINFSource{name: name, data: data, file: file})
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].name < sources[j].name })
	return sources, nil
}

// selectManifestSINFSource resolves only relationships established by the
// manifest and archive itself. Missing replicas are safe when every declared
// source is byte-identical; otherwise the manifest supplies no source index.
func selectManifestSINFSource(sources []manifestSINFSource, target string, targetData []byte, targetPresent bool) (manifestSINFSource, error) {
	for _, source := range sources {
		if source.name == target {
			return source, nil
		}
	}
	if targetPresent {
		for _, source := range sources {
			if bytes.Equal(source.data, targetData) {
				return source, nil
			}
		}
		return manifestSINFSource{}, fmt.Errorf("target SINF %q differs from every declared source", target)
	}
	for _, source := range sources[1:] {
		if !bytes.Equal(source.data, sources[0].data) {
			return manifestSINFSource{}, fmt.Errorf("missing target SINF %q has multiple distinct declared sources", target)
		}
	}
	return sources[0], nil
}

// buildSINFAssociations maps each explicitly declared SINF target to its one
// source. An undeclared image may use its adjacent SINF independently.
func buildSINFAssociations(files map[string]*zip.File) (map[string]string, error) {
	const suffix = "/SC_Info/Manifest.plist"
	var names []string
	for name := range files {
		if strings.HasSuffix(name, suffix) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	result := make(map[string]string)
	for _, name := range names {
		root := strings.TrimSuffix(name, suffix)
		if root == "" || root == ".." || strings.HasPrefix(root, "../") || path.Clean(root) != root || strings.HasPrefix(root, "/") || strings.ContainsAny(root, "\\\x00") {
			return nil, fmt.Errorf("invalid manifest member path %q", name)
		}
		data, err := zipBytes(files[name])
		if err != nil {
			return nil, fmt.Errorf("read manifest %q: %w", name, err)
		}
		var manifest macOSSINFManifest
		_, err = plist.Unmarshal(data, &manifest)
		clear(data)
		if err != nil {
			return nil, fmt.Errorf("parse manifest %q: %w", name, err)
		}
		member := func(relative string) (string, error) {
			if strings.ContainsRune(relative, '\x00') {
				return "", fmt.Errorf("SINF path contains NUL")
			}
			return macOSSINFMember(root, relative)
		}
		sources, err := loadManifestSINFSources(files, root, name, manifest.SINFPaths)
		if err != nil {
			return nil, err
		}
		for _, relative := range manifest.SINFReplicationPaths {
			target, err := member(relative)
			if err != nil {
				clearManifestSINFSources(sources)
				return nil, fmt.Errorf("manifest %q: %w", name, err)
			}
			if _, exists := result[target]; exists {
				clearManifestSINFSources(sources)
				return nil, fmt.Errorf("multiple manifest mappings for SINF %q", target)
			}
			var targetData []byte
			targetFile, targetPresent := files[target]
			if targetPresent {
				if targetFile == nil {
					clearManifestSINFSources(sources)
					return nil, fmt.Errorf("invalid target SINF %q", target)
				}
				targetData, err = zipBytes(targetFile)
				if err != nil {
					clearManifestSINFSources(sources)
					return nil, fmt.Errorf("read target SINF %q: %w", target, err)
				}
			}
			source, selectErr := selectManifestSINFSource(sources, target, targetData, targetPresent)
			clear(targetData)
			if selectErr != nil {
				clearManifestSINFSources(sources)
				return nil, fmt.Errorf("manifest %q: %w", name, selectErr)
			}
			result[target] = source.name
		}
		clearManifestSINFSources(sources)
	}
	return result, nil
}
