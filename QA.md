# Private QA

The control matrix is manual and opt-in. Private captures are never stored in
the repository. Temporary decrypted IPAs are deleted when the command exits.

Build UnfairPlay, create a mode-0600 manifest, then run:

```sh
go build -o /private/tmp/unfairplay ./cmd/unfairplay
go run ./tools/qa-controls \
  --unfairplay /private/tmp/unfairplay \
  --manifest /private/path/controls.json
```

Example manifest:

```json
{
  "schema": "unfairplay-private-qa-v1",
  "controls": [
    {
      "name": "modern-control",
      "capture": "/private/path/App.capture",
      "expected_model_sha256": "...",
      "expected_ipa_sha256": "...",
      "expected_evaluator_source_sha256": "...",
      "expected_reference_code_source": "embedded-profile",
      "expected_images": 10,
      "expected_pages": 11004
    },
    {
      "name": "saved-ipa-control",
      "ipa": "/private/path/App.ipa",
      "model": "/private/path/fairplay-enrollment.bin",
      "expected_model_sha256": "...",
      "expected_ipa_sha256": "...",
      "expected_reference_code_source": "existing-model",
      "expected_images": 39,
      "expected_pages": 10080
    }
  ]
}
```

Capture controls test complete recovery. IPA/model controls test reusable
decryption across other accounts and app layouts. The command fails on any
changed hash, image count, page count, or incomplete decryption. Use it before
creating a release tag.

## IORegistry hardware identity control

On macOS, compare live hardware discovery with a previously verified six-byte
`IOMACAddress` file from the same Mac:

```sh
UNFAIRPLAY_IOMAC_FILE=/private/path/iomac.bin \
go test ./internal/fairplay -run '^TestExternalIORegistryHardwareMAC$' -count=1 -v
```

This exercises the actual `ioreg` query and checks the built-in `en0` interface's
parent address. Discovery queries only subtrees with `IOMACAddress`, avoiding
unrelated registry properties that can contain invalid XML characters. It
still rejects malformed XML and requires a matching built-in interface with a
six-byte parent address. The test prints neither the address nor its hash; do
not commit the private control or a full IORegistry dump.

## macOS IPA conversion control

The private conversion control proves that a version-2 enrollment model derives
the same account credential and output SINF as the independent macOSFairFree
implementation:

For an IPA containing exactly one current SINF, run:

```sh
UNFAIRPLAY_MACOS_CREDENTIAL_MODEL=/private/path/fairplay-enrollment.bin \
UNFAIRPLAY_MACOS_CREDENTIAL_IPA=/private/path/App.ipa \
go test ./internal/fairplay \
  -run TestExternalMacOSCredentialFromEnrollmentModel -count=1 -v
```

For a multi-SINF IPA, extract each distinct source SINF privately and run the
same control directly against it. Byte-identical replicas do not need a
separate run:

```sh
UNFAIRPLAY_MACOS_CREDENTIAL_MODEL=/private/path/fairplay-enrollment.bin \
UNFAIRPLAY_MACOS_CREDENTIAL_SINF=/private/path/App.sinf \
go test ./internal/fairplay \
  -run TestExternalMacOSCredentialFromEnrollmentModel -count=1 -v
```

Run the control for both supported current layouts when fixtures are available:
88-byte rights with a 448-byte private record, and 80-byte rights with a
440-byte private record whose first 432 bytes are encrypted and whose final
eight bytes are zero. Do not commit the model, IPA, SINF, credential, or
converted output.

## Exact-build fallback profile

Regenerate the fail-closed 26A428/26A434 fallback only from the hash-matching
arm64e `fairplayd`:

```sh
go run ./tools/compact-kernel \
  --macho /private/path/fairplayd.arm64e \
  --seed-profile internal/recovery/profiles/macos26a428-compact-cfg.bin.gz \
  --seed-start 0x1000103a8 --seed-start 0x1003384cc \
  --seed-start 0x100484cd0 --seed-start 0x1006dd508 \
  --seed-start 0x100796630 \
  --seed-start 0x100796720 --seed-start 0x1007ead40 \
  --seed-start 0x1007eadc0 --seed-start 0x1008fe5d4 \
  --seed-start 0x10093fe44 --seed-start 0x10093ff14 \
  --seed-start 0x1009f0994 --seed-start 0x100392a58 \
  --compact-output --section-id 11 \
  --output internal/recovery/profiles/macos26a428-safe-extracted.bin.gz
```

Expected output: 52,494 blocks, 1,725 rejected blocks, compressed SHA-256
`66014b69e80e71ede55850c1d535e10d3beeb8019d7bd968753d4a5f140d3544`.
The runtime loads this profile only when the capture includes the exact
hash-matching reference binary.

The exact-image extractor also includes indirect SINF entries `0x100254df4`
(4,840 instructions, ending at `0x100259990`) and `0x1002986d0`
(2,114 instructions, ending at `0x10029a7d4`). These blocks are mechanically
translated, not promoted to verified fallbacks. Their larger extraction bounds
are address-specific, and discovery adds them only for the pinned source hash.
`UNFAIRPLAY_PROFILE_BINARY=/private/path/fairplayd.arm64e go test
./tools/compact-kernel -run 'TestExternal(LongSINFEntries|SeededMachoExtraction)'`
checks source instruction digests, complete translation and extraction geometry.

The existing store-loop tail at `0x100392a58` is shared with SINF recovery via
the verified fallback map. Its two 64-bit stores with post-increment, decrement
and conditional back-edge are checked with synthetic loop counts 1 and 2.
