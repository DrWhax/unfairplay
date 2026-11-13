# UnfairPlay for Binary Ninja

This plugin adds an **iOS IPA (UnfairPlay)** container transform to Binary
Ninja 6.0.10905 or later. It lists the main app first, followed by executable
extensions, frameworks and Watch apps. After CLI decryption, Binary Ninja's
built-in Mach-O and Universal loaders handle the selected executable.

The plugin uses Binary Ninja's [container Transform API](https://docs.binary.ninja/dev/containertransforms.html).
Detection inspects archive metadata only; it never runs the CLI, reads models,
or decrypts an IPA. Extraction uses the same standard-library archive and CLI
helpers as the IDA integration. No enrollment recovery runs inside Python.

## Install

From the repository root or extracted release archive, run on macOS:

```sh
unfairplay_bn_plugin_dir="$HOME/Library/Application Support/Binary Ninja/plugins/unfairplay"
mkdir -p "$unfairplay_bn_plugin_dir"
cp integrations/binaryninja/__init__.py integrations/binaryninja/plugin.json \
  integrations/binaryninja/README.md "$unfairplay_bn_plugin_dir/"
cp integrations/ida/unfairplay_ipa.py LICENSE "$unfairplay_bn_plugin_dir/"
```

On Linux, use `~/.binaryninja/plugins/unfairplay` as the destination. Restart
Binary Ninja. Put `unfairplay` on Binary Ninja's PATH or set
`UNFAIRPLAY_BINARY` to its executable path. The GUI can also locate the CLI
through a file dialog. Windows decryption is unsupported by the CLI.

## Open an IPA

Use **Plugins → UnfairPlay → Open IPA…**, select the IPA, then choose an
executable. The main app is listed first. This global command is also available
from the start screen and explicitly selects the UnfairPlay transform before
decrypting with the saved model. It opens the decrypted executable in a new Mach-O tab.

Binary Ninja's ordinary **File → Open** can automatically choose its built-in
Zip handler, so an UnfairPlay window is not guaranteed to appear through that
route. The ordinary **Zip** branch does not perform FairPlay decryption. The
**UnfairPlayIPA / iOS IPA (UnfairPlay)** container transform remains available
to container sessions and the API; the plugin menu is the direct GUI entry point.

For large IPAs, use `files.container.mode = Interactive` to select executables
before extraction. Full mode can request every executable. The main app is
listed first; choose a Watch app only when you intend to analyze watchOS code.

In the GUI, selecting an encrypted IPA and executable automatically uses the
saved UnfairPlay model; there is no additional enrollment confirmation.
Default model discovery follows `UNFAIRPLAY_MODEL_DIR` and the CLI's normal
macOS/Linux user configuration directories. Set `UNFAIRPLAY_BINARYNINJA_MODEL`
to use an explicit model file or registry directory. An IDA-specific model
override does not select Binary Ninja's model.

If no saved model is found, the plugin explains the one-time terminal setup:

```sh
sudo unfairplay setup --app /Applications/App.app --ipa App.ipa
```

Use the same app and Store enrollment on both sides. Already-decrypted IPAs
load without a model or the CLI. The plugin does not log in, collect enrollment,
or run sudo. The CLI validates model permissions, enrollment matching and
all applicable decryption checks.

The GUI supports cancellation while the CLI runs. Missing pre-encryption hashes
require a separate confirmation. Successful extraction labels the child as
verified, accepted-but-unverified, or already-decrypted input whose authenticity
was not checked. The plugin never reports the last case as verified plaintext.

## Headless use

A license supporting the headless API is required. Use `TransformSession`, set
the root context transform name to `UnfairPlayIPA`, and invoke discovery with
`Transform['UnfairPlayIPA'].decode_with_context(context, params)`. Then select
from `context.available_files` with `context.set_requested_files(...)` and
invoke decoding again. Load each child with `binaryninja.load(child.input)`.
The usual container chain also handles universal Mach-O images.

Headless decryption requires `params={'allow-decryption': b'yes'}`. To accept
plaintext missing pre-encryption hashes, also set `'allow-unverified': b'yes'`.
Neither permission is inferred from the presence of a model. Configure the CLI
and model with environment variables; headless use never opens file dialogs.

## Privacy and validation

The original input stays unchanged. The plugin copies the exact container input
into a private temporary directory for the CLI, strips account data from its
output, and removes temporary IPAs and reports. Selected plaintext images stay
in Binary Ninja's container views and may be saved in BNDBs alongside the
original archive. Keep those databases and any exports private.

Synthetic regression tests run without Binary Ninja:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s integrations/binaryninja/tests -v
```

An opt-in native control is provided in `tests/native_smoke.py`. It uses
synthetic arm64 code and a fake CLI, without private licenses or enrollment
fixtures. Run with Binary Ninja's Python package on the import path under a
headless-capable license, or execute it in the GUI Python console:

```python
import runpy
runpy.run_path('/path/to/unfairplay/integrations/binaryninja/tests/native_smoke.py', run_name='__main__')
```

This does not change or save your current BinaryView. The 21 synthetic
regression tests cover container extraction and the explicit menu path.
Container detection, synthetic CLI extraction and native arm64 Mach-O loading
also passed inside Binary Ninja 6.0.10905's GUI. These controls use no real
enrollment model. The menu's GUI handoff and additional real IPA/model checks
are opt-in; see [QA.md](../../QA.md).
