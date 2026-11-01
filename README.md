# UnfairPlay

UnfairPlay recovers a FairPlay model from an enrolled Mac and uses it to
decrypt personalized iOS IPAs. It is a standalone Go program.

It does not log in to Apple, buy apps, or download IPAs. You can use ipatool or
another downloader for that part.

## Legal and ethical use

Use UnfairPlay only with apps you lawfully acquired and accounts and devices
you control. It is intended for interoperability, preservation, and authorized
research. The authors do not condone piracy, credential theft, copyright
infringement, or unauthorized distribution of decrypted apps.

## Discord

Project discussion and support: [UnfairPlay Discord](https://discord.gg/hpwvuQHfaf).

## Build

```sh
go build -o unfairplay ./cmd/unfairplay
```

## Usage

First, sign in to the native Mac App Store. Install an iPhone or iPad app and
open it once. Download a matching encrypted IPA with the same Apple Account.

Set up reusable decryption once:

```sh
sudo ./unfairplay setup \
  --app /Applications/App.app \
  --ipa App.ipa
```

Large enrollment databases print bounded recovery progress to standard error.
The final JSON result remains on standard output.

The setup result includes `plaintext_verified` for the matching IPA. A successful
setup can report `false` when any decrypted image lacks pre-encryption hashes;
this is separate from whether the model was recovered and saved successfully.

The saved model is private. It is tied to the Mac App Store enrollment, not to
one app, so it can decrypt other personalized IPAs from the same enrollment.
Back it up only in encrypted storage and never share it.

Decrypt another IPA:

```sh
./unfairplay decrypt --input AnotherApp.ipa
```

The default model directory is inside the user configuration directory. Set
`UNFAIRPLAY_MODEL_DIR` or pass `--model` to use another location.

IPAs with extensions and watch apps are decrypted in one pass.

The output keeps the input's `SC_Info` licenses and `iTunesMetadata.plist`,
which identify the Store account. To create a redacted copy for private
analysis or authorized collaboration, add `--strip-account-data`: it omits
every `SC_Info` member and removes the Apple ID and purchaser fields from
`iTunesMetadata.plist`. Redaction does not authorize redistributing the app;
the legal and ethical use terms above still apply. Test without
keeping plaintext with:

```sh
./unfairplay verify --input AnotherApp.ipa
```

The decryption path handles ARMv6/Thumb-1, ARMv7, ARM64, and
ARM64_32/watchOS slices.
Available pre-encryption page hashes must match; a mismatch fails closed.
Older executables without these tables can decrypt, but report
`plaintext_verified=false`.

### Convert an IPA for macOS

This requires an encrypted IPA personalized for the same Store enrollment as
your saved model. Convert it with:

```sh
./unfairplay convert-ipa-macos \
  --input App.ipa \
  --model /private/path/fairplay-enrollment.bin
```

Omit `--model` to use the saved model. The default output is `App.macos.ipa`.
Use `--output` to choose another path or `--force` to replace an existing
output.

The command uses a saved version-2 enrollment model. You can instead use a
matching private 16-byte credential:

```sh
chmod 600 credential.bin
./unfairplay convert-ipa-macos \
  --input App.ipa \
  --credential credential.bin
```

The conversion:

- decodes the current private record with the direct enrollment model;
- validates and rewrites the personalized SINF into the macOS layout;
- preserves its app key, signature, rights, and other private fields;
- adds every SINF copy declared by Apple for encrypted frameworks and
  extensions; and
- leaves all Mach-O executables byte-identical and encrypted.

Model-based conversion supports the observed 440- and 448-byte private SINF
records and the same bounded appended-rights geometry used by recovery.

The result is still an IPA, not a macOS installer. A macOS iOS-app wrapper or
compatible installer must preserve this basic layout:

```text
App iOS.app/
  WrappedBundle -> Wrapper/App.app
  Wrapper/App.app
  Wrapper/iTunesMetadata.plist
```

The converted IPA and wrapper contain a private account license. Keep them
private. This feature does not decrypt, modify, re-sign, or bypass checks inside
the app. Apps may still reject macOS, require unavailable hardware, or depend on
services that are not present on macOS.

## Advanced commands

`collect` and `recover` expose the two setup stages for diagnostics and
archived captures. `doctor` checks a capture, IPA, or model.

```sh
sudo ./unfairplay collect --app /Applications/App.app --ipa App.ipa --output App.capture
./unfairplay recover --capture App.capture --output App.recovery
```

## FAQ

### What is an enrollment?

An enrollment is the FairPlay state created when an Apple Account uses the Mac
App Store on a Mac. It links the account, Mac, and FairPlay selector. `setup`
turns that state into a reusable private model.

### What are SINF, SUPF, SIDB, and SC Info?

- **Personalized SINF:** an app license created for one Store enrollment. It
  identifies the enrollment and protects the app-specific key.
- **SUPF/SUPP:** signed per-executable records used to derive keys and IVs for
  encrypted Mach-O pages. Apps, extensions, frameworks, and watch apps may each
  have one.
- **`SC_Info`:** the directory inside an installed app or IPA that contains its
  SINF and SUPF/SUPP license files.
- **System `SC Info`:** the private Mac FairPlay state directory. Its SIDB and
  SIDS files contain enrollment state, not app content.

These files are private. Do not publish or share them.

### Do I need to run setup for every app?

No. One model can decrypt different IPAs personalized for the same enrollment.
Each app still has its own key inside its personalized SINF.

### Why might another macOS build fail?

Apple can change enrollment state layouts or semantic tables. UnfairPlay
follows explicit SIDB version, state-slot, root-cursor, and selector rules.
An unmapped format or tag-constructor path stops recovery with an error. It never
publishes a model until the matching IPA decrypts and passes the applicable
validation checks; missing plaintext hashes remain explicitly unverified.

Patches and test reports are welcome. Include the macOS build, UnfairPlay
commit, and a redacted error. Keep app identities, identifying IPA measurements
and private paths out of public reports. Never share SIDB, SINF, hardware
identity, enrollment models, decrypted apps, or Apple credentials.

### Can decryption run on another operating system?

Yes. Collection must start on an enrolled Mac. You can either run `setup` on
that Mac and securely copy the resulting model, or copy a complete private
`collect` bundle and run `recover` elsewhere. The bundle contains the installed
license files, system SC Info state, built-in IOMACAddress, matching IPA, and
macOS build metadata.

The recovered model and personalized IPAs can then be used on macOS or Linux;
the native fairplayd daemon is never launched by this tool. Windows builds
compile, but Windows decryption is not enabled until equivalent private-file
permission checks are implemented.

## Support

Recovery follows the mapped current-container and tree format. It derives one
state slot, a hardware-dependent root cursor and tag codebook, then selects the
SINF's exact user/key path and authenticates its single value. It does not try
other records or windows when that value fails authentication. Only the mapped
tree format is supported.

Private recovery reports include the selected container, slot, tree, leaf and
record geometry. The private QA matrix pins that layout so a parser change
cannot silently select another route.

The hardware tag constructor uses a byte mixer followed by AES-CBC and an
affine map of each output word. Selection-state derivation processes the
selected prefix with AES-CBC and a final AES key transform. All constants are
part of the mapped algorithm. Production loads no native executable or
constructor profile. Support is determined by format and authenticated route;
unknown versions, tags and selected-route geometry fail closed. SINF
authentication, complete IPA processing, and every applicable validation check
remain mandatory. Older IPAs without pre-encryption hashes remain explicitly
unverified rather than being reported as verified.

IPA decryption uses explicit `SC_Info/Manifest.plist` SINF replication paths,
or the executable's adjacent SINF when no mapping is declared. Paired legacy
and v5 SUPFs must have identical architecture and page records; a legacy SUPF's
signature-blob hash must match its executable. Conflicts within the selected
page-key class fail closed. Recovery uses one canonical set of runtime inputs
without a broader license retry. Mach-O images can also use signed
`.supp`/`.v4.supp` page tables, indexed from file offset zero. Universal tables
use absolute file-page indexes and must cover every encrypted slice exactly.
Legacy universal signature bindings cover the concatenated slice signatures
in fat-header order.
Architecture-indexed SUPF files take precedence when present; a malformed
selected class never triggers a retry with the other class. SINF manifests
may declare multiple sources. Existing replicas must match one source exactly;
a missing replica is accepted only when every declared source is identical.
Ambiguous mappings fail closed.

Plaintext validation checks every CodeDirectory pre-encryption hash slot that
intersects an encrypted range. Instruction scoring and sampled-page checks are
not used. Every available pre-encryption table is checked. Older directories
or a zero pre-encryption offset mean no table; a malformed nonzero table fails
closed.

Images with no table report validation as unavailable, and the overall
`plaintext_verified` flag is false if any image lacks coverage. These checks
establish consistency with the embedded hashes, not Apple CMS signature trust.
Unencrypted pages outside those ranges are not covered by this plaintext check.
Decryption reports use `unfairplay-decryption-v2`; consumers of the removed
instruction-audit fields must migrate to the plaintext validation fields.

macOS arm64 and Linux amd64/arm64 are supported. Windows is compile-tested but
cannot yet enforce the required private-file permissions.

During setup, the installed app, matching IPA, Mac state, and hardware identity
must belong to the same enrollment. The resulting model can then decrypt other
IPAs personalized for that enrollment. Account or selector mismatches are
rejected.

Keep capture and model files private. Do not share SIDB, SINF, hardware data,
recovery models, or decrypted apps. Decrypted IPAs are analysis files and need
signing before installation.

## Reporting problems

Private controls do not establish support for every layout or independent
enrollment. Do not infer support from the macOS build alone.
Build it from source and run `setup` normally. Confirm the binary with
`./unfairplay --version`. Reports should include only that version output, the
macOS build and a redacted error. Keep app identities, IPA measurements,
account/hardware identifiers and private paths out of public reports. Never
attach SIDB, SINF, hardware identity, models, credentials, or
decrypted IPAs to a public issue.

## Releases

Run the private control matrix in [QA.md](QA.md) before tagging a release.

Tags matching `v*` publish binaries and `SHA256SUMS` through GitHub Actions.
Tags such as `v0.2.0-rc.1` create prereleases.

## License

MIT. Third-party notices are in `NOTICE`, `LICENSE-DARKPHOENIX.txt`, and
`LICENSE-MACOSFAIRFREE.txt`.
