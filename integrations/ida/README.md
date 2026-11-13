# UnfairPlay for IDA Pro 9+

This Python archive-loader plugin offers decryption when you open an encrypted
IPA, then hands the selected plaintext executable to IDA's built-in Mach-O
loader. It runs on macOS and Linux and needs only IDAPython's standard library
plus the UnfairPlay command-line executable.

## Install

Build the current CLI from the repository root:

```sh
go build -o unfairplay ./cmd/unfairplay
```

Copy `unfairplay_ipa.py` into your IDA user directory's `loaders` subdirectory.
For the default macOS/Linux user directory, run from the repository root:

```sh
mkdir -p ~/.idapro/loaders
cp integrations/ida/unfairplay_ipa.py ~/.idapro/loaders/
```

Restart IDA. This file belongs in `loaders`, because it must run before the
executable is loaded into a database. See Hex-Rays' documentation on
[user loaders and IDAUSR](https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr).
It does not appear in the Edit > Plugins menu.

Put `unfairplay` on the PATH inherited by IDA, or set `UNFAIRPLAY_BINARY` to its
executable path before starting IDA. If it cannot be found, the loader opens a
file dialog to locate it. Environment variables set in a terminal apply to IDA
only when it inherits that terminal's environment; GUI launches may differ.

## Use

1. Open an `.ipa` in IDA and select **iOS IPA (UnfairPlay)** in the loader dialog
   if multiple formats are offered.
2. Choose the main executable (selected by default), an extension, or a framework.
3. If any IPA image is encrypted, accept the decryption offer. The CLI validates
   the enrollment against the IPA and decrypts it. IDA then loads your selected
   executable normally, including its usual architecture selection for fat images.

A decrypted IPA opens directly without needing an enrollment or the CLI.
Cancellation stops the decryption subprocess and removes its temporary files.
An error from the CLI aborts loading; there are no enrollment, license or key
fallback attempts in the plugin.

## One-time enrollment

If no saved model is found, the plugin shows these instructions and stops.
On an enrolled Mac, sign in to the native Mac App Store, install an iPhone/iPad
app and launch it once. In a terminal, use that app and a matching encrypted IPA:

```sh
sudo unfairplay setup --app /Applications/App.app --ipa App.ipa
```

Setup saves reusable enrollment models; reopen the IPA in IDA afterward. Other
IPAs must be personalized for that same enrollment. The plugin never runs sudo,
collects system enrollment state, or asks for Apple credentials.

Model discovery checks, in order:

- `UNFAIRPLAY_IDA_MODEL`: explicit private model file or directory.
- `UNFAIRPLAY_MODEL_DIR`: UnfairPlay's configured model directory.
- macOS: `~/Library/Application Support/unfairplay/models`.
- Linux: `$XDG_CONFIG_HOME/unfairplay/models`, or `~/.config/unfairplay/models`.

Discovery establishes only that a model file exists. The CLI validates its
format, private permissions, enrollment match and authenticated decryption.
An invalid or mismatched model produces the CLI error instead of being treated
as a missing enrollment. Linux can use a model securely recovered on the Mac;
Windows decryption is currently unsupported by UnfairPlay.

## Plaintext and verification

The input IPA is unchanged. The CLI is called with `--strip-account-data`; the
temporary decrypted IPA and private report are deleted after extracting your
selected executable. The extracted executable is created mode 0600 and handed
to IDA as its archive temporary file. IDA owns that file's lifecycle; the IDB
contains plaintext code. Keep the IDB and any exported code private.

A successful CLI result with `PlaintextVerified=false` requires a separate
confirmation, defaulting to No. It means one or more decrypted images lack
pre-encryption hashes; it is not reported as verified plaintext.

The loader rejects ambiguous apps, duplicate archive members, unsafe paths,
symlinks, malformed encryption headers, and unknown encryption IDs. The CLI
remains the authority for SINF/SUPF authentication and page verification.

## Validation

From the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s integrations/ida/tests -v
```

The unit tests use synthetic archives, mocked IDA dialogs, and a subprocess
stub. An additional opt-in test loads synthetic IPAs through the installed
IDA 9.4 archive-loader chain and native Mach-O loader:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 integrations/ida/tests/native_smoke.py
```

That test requires `IDADIR` pointing to the licensed IDA 9.4 installation and
its `idapro` package on Python's import path (follow the installation's
`idalib/README.txt`). It adds a temporary loader directory to IDAUSR and uses
a synthetic CLI in place of real FairPlay decryption. It does not install the
loader in your profile or use private enrollment fixtures. GUI dialogs and
real encrypted IPA/model pairs still require the opt-in private checks in
[QA.md](../../QA.md).
