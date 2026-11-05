package fairplay

import (
	"archive/zip"
	"fmt"
	"os"
)

type ipaLicense struct {
	material KeyMaterial
	mask     [16]byte
	deriver  *pageKeyDeriver
}

type licenseReport struct {
	Member           string         `json:"member"`
	Provider         string         `json:"provider"`
	ModelBuild       string         `json:"model_build"`
	LogicalKeySHA256 string         `json:"logical_key_sha256"`
	Oracle           map[string]any `json:"oracle"`
}

// resolveIPALicenses resolves every executable's adjacent license before any
// decrypted output is staged. A model directory may serve several selectors.
func resolveIPALicenses(inventory ipaInventory, files map[string]*zip.File, modelPath string) (map[string]*ipaLicense, []licenseReport, error) {
	resolve := ResolveLogicalKey
	if modelPath != "" {
		info, err := os.Stat(modelPath)
		if err != nil {
			return nil, nil, fmt.Errorf("inspect FairPlay enrollment model: %w", err)
		}
		if info.IsDir() {
			packs, err := readEnrollmentModelRegistry(modelPath)
			if err != nil {
				return nil, nil, err
			}
			defer clearModelPacks(packs)
			resolve = func(sinf []byte) (KeyMaterial, error) {
				return ResolveLogicalKeyWithModels(sinf, packs)
			}
		} else {
			pack, err := readEnrollmentModel(modelPath)
			if err != nil {
				return nil, nil, err
			}
			defer clear(pack)
			resolve = func(sinf []byte) (KeyMaterial, error) {
				return ResolveLogicalKeyWithModel(sinf, pack)
			}
		}
	}

	licenses := make(map[string]*ipaLicense)
	var reports []licenseReport
	complete := false
	defer func() {
		if complete {
			return
		}
		for _, license := range licenses {
			clear(license.material.LogicalKey[:])
			clear(license.mask[:])
		}
	}()
	for _, image := range inventory.images {
		if _, ok := licenses[image.sinfMember]; ok {
			continue
		}
		file := files[image.sinfMember]
		if file == nil {
			return nil, nil, fmt.Errorf("missing inventoried SINF %q", image.sinfMember)
		}
		sinf, err := zipBytes(file)
		if err != nil {
			return nil, nil, err
		}
		material, err := resolve(sinf)
		sinfHash := digest(sinf)
		clear(sinf)
		if err != nil {
			return nil, nil, fmt.Errorf("SINF %q: %w", image.sinfMember, err)
		}
		if material.Evidence == nil {
			material.Evidence = make(map[string]any)
		}
		material.Evidence["request_ipa_sha256"] = inventory.sha256
		material.Evidence["request_sinf_sha256"] = sinfHash
		mask := appMaskFromLogicalKey(material.LogicalKey)
		licenses[image.sinfMember] = &ipaLicense{
			material: material, mask: mask, deriver: newPageKeyDeriver(mask),
		}
		provider, _ := material.Evidence["provider_kind"].(string)
		if provider == "" {
			provider = "unknown"
		}
		model, _ := material.Evidence["model_name"].(string)
		if model == "" {
			model = "unknown"
		}
		reports = append(reports, licenseReport{
			Member: image.sinfMember, Provider: provider, ModelBuild: model,
			LogicalKeySHA256: digest(material.LogicalKey[:]), Oracle: material.Evidence,
		})
	}
	complete = true
	return licenses, reports, nil
}
