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

## Exact-build fallback profile

Regenerate the fail-closed 26A428/26A434 fallback only from the hash-matching
arm64e `fairplayd`:

```sh
go run ./tools/compact-kernel \
  --macho /private/path/fairplayd.arm64e \
  --seed-profile internal/recovery/profiles/macos26a428-compact-cfg.bin.gz \
  --seed-start 0x1000103a8 --seed-start 0x1007ead40 \
  --seed-start 0x1007eadc0 --seed-start 0x1008fe5d4 \
  --seed-start 0x10093fe44 --seed-start 0x10093ff14 \
  --seed-start 0x1009f0994 \
  --seed-start 0x10075e008 --seed-start 0x1006b2828 \
  --compact-output --section-id 11 \
  --output internal/recovery/profiles/macos26a428-safe-extracted.bin.gz
```

Expected output (before adding the 25C56 seed-starts): 52,496 blocks, 1,726
rejected blocks, compressed SHA-256
`40be55e94f23df470ccb51a8e98f910fa0ba7731ceb20ce070d551eac06d7f96`.
After adding `--seed-start 0x10075e008 --seed-start 0x1006b2828` the block
count, rejected count, and digest will change; update the embedded digest in
`compact_profile_safe_extracted.go` and the expected values above after running
the command against the 26A428 `fairplayd.arm64e` binary.
The runtime loads this profile only when the capture includes the exact
hash-matching reference binary.
