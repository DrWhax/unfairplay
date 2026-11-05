package fairplay

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

type KeyMaterial struct {
	LogicalKey [16]byte
	Evidence   map[string]any
}

func digest(blob []byte) string {
	value := sha256.Sum256(blob)
	return hex.EncodeToString(value[:])
}

func ResolveLogicalKey(sinf []byte) (KeyMaterial, error) {
	selector, err := ParseSINFSelector(sinf)
	if err != nil {
		return KeyMaterial{}, err
	}
	fields, err := parseSINFFields(sinf)
	if err != nil {
		return KeyMaterial{}, err
	}
	private, err := sinfPrivatePayload(sinf, fields)
	if err != nil {
		return KeyMaterial{}, err
	}
	return KeyMaterial{}, fmt.Errorf(
		"FairPlay profile %s (sinf_sha256=%s priv_bytes=%d priv_sha256=%s) requires a private enrollment model; pass --model FILE or --model DIRECTORY",
		selector.Identifier(), digest(sinf), len(private), digest(private),
	)
}

// ResolveLogicalKeyWithModel resolves a SINF with an experimental external
// model. Model packs are intentionally data, not Go code, so research models
// can be tested without changing the portable decryption path.
func ResolveLogicalKeyWithModel(sinf, pack []byte) (KeyMaterial, error) {
	model, err := parseCurrentSINFModel(pack)
	if err != nil {
		return KeyMaterial{}, err
	}
	modelSHA256 := digest(pack)
	modelName := "external-current-sinf-" + modelSHA256[:16]
	supportedSelector := ""
	if model.hasSelector {
		supportedSelector = model.selector.Identifier()
	}
	return resolveLogicalKey(sinf, model, modelName, modelSHA256, "external-enrollment-model", supportedSelector)
}

// ResolveLogicalKeyWithModels selects one model by both selector and complete
// SINF validation. Several model types may share a selector, but exactly one
// must decode the requested SINF. Version-1 packs remain supported as an
// explicit --model file, but are rejected in registries without a selector.
func ResolveLogicalKeyWithModels(sinf []byte, packs [][]byte) (KeyMaterial, error) {
	selector, err := ParseSINFSelector(sinf)
	if err != nil {
		return KeyMaterial{}, err
	}
	var selected KeyMaterial
	selectedCount := 0
	matchedSelector := false
	for index, pack := range packs {
		model, parseErr := parseCurrentSINFModel(pack)
		if parseErr != nil {
			return KeyMaterial{}, fmt.Errorf("parse FairPlay model %d: %w", index, parseErr)
		}
		if !model.hasSelector {
			return KeyMaterial{}, fmt.Errorf("FairPlay model %d is version 1 and cannot be used in a registry", index)
		}
		if model.selector != selector {
			continue
		}
		matchedSelector = true
		candidate, resolveErr := ResolveLogicalKeyWithModel(sinf, pack)
		if errors.Is(resolveErr, errCurrentSINFProfileMismatch) {
			continue
		}
		if resolveErr != nil {
			clear(selected.LogicalKey[:])
			return KeyMaterial{}, fmt.Errorf("FairPlay model %d: %w", index, resolveErr)
		}
		selectedCount++
		if selectedCount > 1 {
			clear(selected.LogicalKey[:])
			clear(candidate.LogicalKey[:])
			return KeyMaterial{}, fmt.Errorf("FairPlay model registry has multiple models that decode SINF for selector %s", selector.Identifier())
		}
		selected = candidate
	}
	if selectedCount == 1 {
		return selected, nil
	}
	if matchedSelector {
		return KeyMaterial{}, fmt.Errorf("FairPlay model registry has no model that decodes SINF for selector %s", selector.Identifier())
	}
	return KeyMaterial{}, fmt.Errorf("FairPlay model registry has no model for selector %s", selector.Identifier())
}

func resolveLogicalKey(sinf []byte, model currentSINFModel, modelName, modelSHA256, stateOrigin, supportedSelector string) (KeyMaterial, error) {
	var result KeyMaterial
	fields, err := parseSINFFields(sinf)
	if err != nil {
		return result, err
	}
	selector, err := sinfSelector(sinf, fields)
	if err != nil {
		return result, err
	}
	private, err := sinfPrivatePayload(sinf, fields)
	if err != nil {
		return result, err
	}
	profile := fmt.Sprintf(
		"%s (sinf_sha256=%s priv_bytes=%d priv_sha256=%s)",
		selector.Identifier(), digest(sinf), len(private), digest(private),
	)
	if supportedSelector != "" && selector.Identifier() != supportedSelector {
		return result, fmt.Errorf(
			"enrollment model is bound to selector %s, but IPA has %s",
			supportedSelector, profile,
		)
	}
	innerKey, err := currentSINFPrivateKey(model, sinf, fields)
	if err != nil {
		if errors.Is(err, errCurrentSINFProfileMismatch) {
			return result, fmt.Errorf("enrollment model cannot decode SINF %s; recover a model from the account that acquired this IPA: %w", profile, err)
		}
		return result, fmt.Errorf("decode SINF %s with enrollment model: %w", profile, err)
	}
	defer clear(innerKey[:])
	logical := logicalFromInnerKey(innerKey)
	result.LogicalKey = logical
	providerKind := "current-sinf-whitebox-direct-v1"
	if model.version == 3 {
		providerKind = "current-sinf-whitebox-direct-v3"
	}
	result.Evidence = map[string]any{
		"provider_kind":          providerKind,
		"provider_status":        0,
		"selector_status":        0,
		"status_patched":         false,
		"device_state_imported":  false,
		"state_origin":           stateOrigin,
		"hardware_backend":       "none",
		"runtime_hardware_calls": 0,
		"request_selector":       selector.Identifier(),
		"model_name":             modelName,
		"model_sha256":           modelSHA256,
		"model_version":          model.version,
		"model_identity_sha256":  hex.EncodeToString(model.modelIdentity[:]),
		"logical_key_sha256":     digest(logical[:]),
	}
	return result, nil
}
