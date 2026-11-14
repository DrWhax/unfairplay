# Private QA

The control matrix is manual and opt-in. Private captures are never stored in
the repository. Temporary decrypted IPAs are deleted when the command exits.
Keep exact control hashes, IPA sizes, page counts and app identities in the
private manifest and logs. Shared summaries should use anonymous control labels
and omit account/hardware identifiers and identifying IPA measurements. Public
OS and format constants are not private control measurements.

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
      "expected_reference_code_source": "typed-go",
      "expected_images": 10,
      "expected_pages": 11004,
      "expected_plaintext_verified": true,
      "expected_recovery_iterations": 284,
      "expected_recovery_state_sha256": "...",
      "expected_registry_candidates": 1,
      "expected_recovery_layout": {
        "container_bytes": 991,
        "codec_bytes": 27,
        "payload_bytes": 944,
        "source_bytes": 224,
        "selector_modulus": 12,
        "selected_slot": 5,
        "root_cursor": 2,
        "root_length": 942,
        "root_child_count": 2,
        "tree_nodes": 17,
        "registry_records": 3,
        "root_version": 65537,
        "account_version": 65538,
        "type_cursor": 100,
        "type_length": 24,
        "sign_cursor": 124,
        "sign_length": 148,
        "value_cursor": 272,
        "value_length": 36,
        "selected_record_index": 2,
        "selected_payload_offset": 292,
        "selected_window_offset": 0,
        "sinf_selector": "12345678:00000002"
      }
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

Capture controls should pin the recovery state hash, iteration count, decoded
registry count, complete recovery layout, model hash, IPA hash, image/page
counts, and plaintext result. The layout and SINF selector are private.
IPA/model controls test reusable
decryption for the supplied selectors and app layouts; independent-account
coverage requires separate account controls. The command fails on any
changed hash, image count, page count, or incomplete decryption. Use it before
creating a release tag.

## IORegistry hardware identity control

On macOS, compare live hardware discovery with a previously verified six-byte
`IOMACAddress` file from the same Mac:

```sh
UNFAIRPLAY_IOMAC_FILE=/private/path/iomac.bin \
go test ./pkg/fairplay -run '^TestExternalIORegistryHardwareMAC$' -count=1 -v
```

This exercises the filtered `ioreg` query and checks the built-in `en0`
interface's parent address. The test prints neither the address nor its hash.
Do not commit the private control or a full IORegistry dump.

## macOS IPA conversion control

The private conversion control proves that a version-2 enrollment model derives
the same account credential and output SINF as the independent macOSFairFree
implementation:

```sh
UNFAIRPLAY_MACOS_CREDENTIAL_MODEL=/private/path/fairplay-enrollment.bin \
UNFAIRPLAY_MACOS_CREDENTIAL_IPA=/private/path/App.ipa \
go test ./pkg/fairplay \
  -run TestExternalMacOSCredentialFromEnrollmentModel -count=1 -v
```

Run available controls for the observed 440- and 448-byte private SINF forms.
Also test bounded extended-rights records when a private control exists. Do not
commit the model, IPA, SINF, credential, or converted output.

For direct-enrollment models, require the converter to decode the current SINF
through the model before writing the legacy wrapper. Keep the older credential-
wrapped version-2 model test as a compatibility control.

## 32-bit ARM decryption controls

Use private IPAs that contain encrypted ARMv6/Thumb-1 and ARMv7 slices when
available. Require every 32-bit ARM report entry to contain:

```text
architecture=armv6 or armv7
cryptid_after=0
plaintext_validation=code-directory-pre-encryption-hashes
pre_encryption_code_directories[*].matched_slots=pre_encryption_code_directories[*].slot_count
```

The public suite has a complete synthetic ARMv6/Thumb-1 decryption and
wrong-key rejection control. The private matrix also retains one ARMv6-only
iOS 3.0-era control. It has no pre-encryption hash table, so QA pins its exact
decrypted output while requiring `plaintext_verified=false`. Prefer the same
real app version from two independent Store enrollments. All Mach-O
members must decrypt byte-identically; only personalized SINF and Store
metadata may differ. Retain wrong-first-page and wrong-final-page key tests
that must fail the pre-encryption hash audit, plus missing-table acceptance
with unavailable plaintext validation and rejection of malformed present tables.
Include thin 32-bit SUPP controls when available. Native execution and
independent-enrollment coverage are separate validation goals.

## Compact frame AES profile

The test-only frame suffix uses direct keyed AES S-box transitions and nine
sparse `GF(2^8)` mixing layers. The larger affine SPN is retained only as an
independent test oracle. Verify all 4,096 deterministic controls with:

```sh
go test ./internal/recovery -run '^TestFrameAESProfile$' -count=1
```

Expected size: 2,065 bytes. Expected compressed SHA-256:
`9d42fb362c39a1f5e1c152fb82fa371869afa0701bec3065b89fba10915af202`.
The decoded checked profile is 4,940 bytes including its checksum, with
SHA-256 `33b7a8b3d13d7d5d09d665f52f5f887c426bd04e119b604d09136585b2ae0945`.
The test-only affine-SPN oracle remains 17,024 bytes with SHA-256
`f1cb13c0056a4125387f98a575c21cc6129438580e48c76373e333df614ea963`.

## Typed inverse-AES/XOR SIDB-key producer

The test-only producer composes away the protected producer's separate stage encodings.
It is ten direct AES inverse-S-box layers, nine fixed
`InvShiftRows + InvMixColumns` operations, four final XOR graphs, and compact
input/output maps. The first inverse-S-box key is zero; all of its former masks
fold into the next round key. Per-round byte orders and matrices are gone.
Verify all 4,096 deterministic controls against the larger test-only SPN with:

```sh
go test ./internal/recovery -run '^TestSIDBProducerTypedMatchesSPNOracle$' -count=1
```

Expected size: 390 bytes. Expected compressed SHA-256:
`a1ddefeea78738a85699db79f2a2c1687b87201c69f43db944e80cbd696ee5be`.
The decoded checked profile is 528 bytes including its checksum, with
SHA-256 `7c0b374de0559f5aa5e743e358b1247636100051e98172542256332ba421b4b9`.

The original private controls can regenerate the larger normalization oracle:

```sh
UNFAIRPLAY_SIDB_PRODUCER_PROFILE=/private/path/producer.bin.gz \
UNFAIRPLAY_SIDB_KEY_LAYER_PROFILE=/private/path/key-layer.bin \
UNFAIRPLAY_SIDB_KEY_REPORT_INPUT=/private/path/key-controls.json \
UNFAIRPLAY_SIDB_PRODUCER_SPN_OUTPUT="$PWD/internal/recovery/profiles/macos26a428-sidb-producer-spn-oracle.bin.gz" \
go test ./internal/recovery -run '^TestSIDBProducerSPNResearch$' -count=1
```

The test-only oracle is 1,618 bytes. Its compressed SHA-256 is
`7f31d8e3b36bcd2981ff2edd8d742d83616c925a9a5c744c868af8e576edc904`.
The 43,392-byte decoded profile has SHA-256
`f9362ea765534d3a3e578f5e40d3814d8cfa57dc67306aadf0e0e698b4344954`.

## Recovery and decryption checks

Run the public suite before submitting a change:

```sh
go test ./...
go vet ./...
go test -race ./...
```

Recovery derives one state slot, hardware-selected tree root and user/key route.
The selected license value must authenticate; failures must not select another
record, source window or license file. Tests cover unsupported versions,
malformed tree spans, duplicate selected-route entries, conflicting page-key
metadata, wrong selectors and authentication failures.

Tree offsets denote native length-field cursors: length at +0, tag at +4,
identifier at +8, child count at +14, and children or payload at +20. Recovery
requires the mapped root schemas `0x10001`/`0x10002`, account schema `0x10002`,
a 24-byte `type` leaf, a 148-byte `sign` leaf, and a 36-byte first `valu` leaf.
The value leaf contains exactly 16 payload bytes. Unknown schemas, unsupported
selected-route tags and duplicate selected entries reject. Parser bounds and
depth limits are tool restrictions, not a native malformed-input specification.

The tag constructor and selection-state cipher use public algorithm constants.
Private captures are not needed by the standard suite. To validate complete
recovery, use a capture control in the matrix above: recover a fresh model and
require the established model and decrypted-archive hashes. Reusing a model
checks decryption but does not exercise the constructor or selection pipeline.
Independent-enrollment coverage requires separate account controls.

Optional source/body and class-key comparisons use:

```sh
UNFAIRPLAY_TEST_CAPTURE=/private/path/App.capture \
UNFAIRPLAY_SIDB_SOURCE_ORACLE=/private/path/source.bin \
UNFAIRPLAY_SIDB_BODY_ORACLE=/private/path/body.bin \
UNFAIRPLAY_CLASS_OPERANDS_ORACLE=/private/path/class-key.bin \
go test ./internal/recovery \
  -run 'TestSIDBNativeSourceAndBodyOracle|TestAccountClassKeyNativeOracle' \
  -count=1 -v
```

Require both tests to run rather than skip. Native controls establish behavior
only for the supplied inputs; they do not establish every account layout or
future format. Keep private inputs and exact identifying measurements outside
the repository and public reports.

## Page-key formats and plaintext validation

Test architecture-indexed SUPF and thin- and universal-image SUPP containers.
Universal SUPP records use absolute file-page indexes and must end exactly at
the final encrypted range. A legacy universal SUPP binds the concatenation of
each slice's complete code-signature payload in fat-header order. SUPF takes
precedence when present; a malformed selected class must fail. Conflicting
variants in that class reject. SUPP page records use file-origin indexing, and
legacy signature-blob bindings must match the executable. Multi-source SINF
manifests must resolve each existing replica to an exact source. A missing
replica is valid only when all declared sources are byte-identical.
Retain one private dual-architecture IPA control with SUPFs removed and require
its SUPP-only decrypted Mach-O hashes and page counts to match the SUPF control.

Recovery authenticates its supplied page-key envelopes. SUPP decryption also
verifies its selected envelope; standalone SUPF decryption checks geometry,
binding and page hashes without verifying its certificate signature. Production
does not establish Apple CMS trust, and `signature_verified` remains false.

Require ciphertext CodeDirectory hashes and exact mutation scope to match.
Every available pre-encryption hash table must match all slots intersecting the
encrypted range. Missing tables produce `plaintext_verified=false` and
`plaintext_validation=unavailable-no-pre-encryption-hashes`; malformed present
tables reject. Include wrong-first-page and wrong-final-page negative controls.
Disassembly or agreement between implementations does not replace plaintext
hash coverage or a native execution control.

Apple's public XNU pager validates source pages and carries their signing status
into the decryption path. Source ciphertext consistency and optional plaintext
hash checks therefore answer different questions. Neither establishes complete
fairplayd or kernel policy equivalence.

References: [XNU pager](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/vm/vm_apple_protect.c),
[CodeDirectory pre-encryption slots](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/codedirectory.h),
[SUPP format](https://github.com/vnc0/fairplay-scinfo).

## Reports

Decryption reports use `unfairplay-decryption-v2`. Consumers should read
`plaintext_validation` and `pre_encryption_code_directories`; the overall
`plaintext_verified` flag is true only when every decrypted image has coverage.
The `recover` and `verify` summaries expose this boolean as well.

For schema compatibility, `supf_member` names the selected page-key file even
when it is a SUPP. Canonical capture metadata uses `architectures` for SUPFs and
`file_origin_pages` for SUPPs; SUPP has no architecture identifier.

## Decrypted IPA to macOS app control

Synthetic parser and archive controls run with `go test ./...`. On an Apple
silicon Mac with Xcode command line tools, also run:

```sh
UNFAIRPLAY_TEST_MACOS_CONVERSION=1 go test ./pkg/fairplay \
  -run '^TestNativeMacOSAppConversion$' -count=1 -v
```

This compiles a synthetic program, changes its input platform to iOS, converts
it back to Catalyst, verifies the signed app with native `codesign`, and runs
the synthetic executable. It uses no private fixtures and does not establish
UIKit, LaunchServices, or third-party application runtime compatibility.
Private application launch checks are manual and opt-in; report anonymous
control labels only. Conversion's `runtime_verified` remains false even when
its signature is valid.

## IDA Pro 9.4 IPA loader control

Run the synthetic controls with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s integrations/ida/tests -v
```

The opt-in native control in `integrations/ida/tests/native_smoke.py` requires a
licensed IDA 9.4 installation and `idapro` on Python's import path. It exercises
archive loader discovery and Mach-O handoff with synthetic IPAs and a fake CLI.
It does not establish real enrollment decryption inside IDA or verify GUI
interaction. See `integrations/ida/README.md` for invocation details.

For a manual private control, install the loader and open an enrolled encrypted
IPA. Confirm the decryption prompt appears, the CLI completes, and the selected
executable loads as Mach-O with plaintext instructions. Also check an already
decrypted IPA; no model; a wrong enrollment; declined decryption; cancellation;
missing pre-encryption hashes; and reopening a saved IDB. Temporarily override
`UNFAIRPLAY_IDA_MODEL` to test missing and wrong enrollment cases without moving
or modifying the saved models. Report only anonymous control labels, GUI/CLI
outcomes and verification booleans; keep IPAs, IDBs, paths and diagnostics private.

## Binary Ninja IPA container control

Run the synthetic regressions without Binary Ninja:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s integrations/binaryninja/tests -v
```

The opt-in native control in `integrations/binaryninja/tests/native_smoke.py`
uses synthetic arm64 code and a fake CLI. It checks transform registration,
discovery, extraction and native Mach-O loading without changing the current
user view. It can run inside the Binary Ninja GUI's Python console or under
a headless-capable license; see `integrations/binaryninja/README.md`.

For private manual testing, use Plugins → UnfairPlay → Open IPA…, confirm an
enrolled encrypted IPA decrypts, and inspect plaintext instructions in the
selected executable. Also test a decrypted IPA, missing/mismatched models,
cancellation, declined unverified-plaintext confirmation, missing hashes,
nested executables, universal architecture selection and reopening a BNDB. Confirm temporary IPA/report
files are removed. The ordinary Zip transform must not be mistaken for the
UnfairPlay transform. Keep BNDBs, original archives, models, identifying
measurements and private diagnostics out of shared reports.

## Experimental app-only enrollment control

On the app-only setup branch, first run a read-only installed-bundle control:

```sh
UNFAIRPLAY_INSTALLED_APP=/Applications/App.app \
  go test ./pkg/fairplay -run '^TestExternalInstalledValidationIPA$' -count=1 -v
```

Optionally set `UNFAIRPLAY_INSTALLED_MODEL` to an existing private model or
registry directory to test full decryption of the reconstructed archive.
Temporary encrypted archives, plaintext and reports are removed by the test.

Then exercise fresh recovery in an isolated private model directory:

```sh
sudo ./unfairplay setup --app /Applications/App.app --model-dir /private/path/test-models
./unfairplay verify --input App.ipa --model /private/path/test-models
```

The independent IPA must match the enrollment. Confirm setup reports
`validation_source=installed-app`, and record `plaintext_verified` separately
for the reconstructed bundle and independent IPA. Do not treat missing hashes
as verified. Also exercise explicit `--ipa`: it must report `provided` and
must never retry using the installed bundle when its validation fails.

Synthetic controls cover whole-bundle preservation, nested encrypted images,
end-to-end archive decryption, private permissions, missing licenses, malformed
and unencrypted images, unsafe names, symlinks, collisions and provenance.
Keep private control data out of the worktree and shared reports.

### App-only experiment evidence

One private installed-app control completed fresh setup without `--ipa`, with
`validation_source=installed-app` and `plaintext_verified=true`. The newly
recovered model was byte-identical to the previously saved reference model.
It also passed the private QA matrix against two separately downloaded IPA
controls from the same enrollment, including a second app. Both controls
reported verified plaintext and retained no plaintext artifacts. The matrix
pinned model/output hashes and image/page counts in a private manifest.

These controls establish this installed-bundle layout and enrollment only;
other installed variants, accounts and missing-hash cases require their own
controls. No private fixture data or identifying measurements are committed.
