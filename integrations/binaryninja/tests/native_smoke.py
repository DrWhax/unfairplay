"""Opt-in native Binary Ninja container/Mach-O control using synthetic data.

Run in a licensed headless interpreter, or with runpy.run_path() in Binary
Ninja's Python console. No current user BinaryView is changed or saved.
"""
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import struct
import tempfile
import zipfile


def synthetic_macho(encrypted=False):
    data = bytearray(8192)
    base = 0x100000000
    struct.pack_into("<8I", data, 0, 0xfeedfacf, 0x100000c, 0, 2, 2, 176, 0, 0)
    struct.pack_into("<II16sQQQQIIII", data, 32, 0x19, 152, b"__TEXT", base, 8192, 0, 8192, 5, 5, 1, 0)
    struct.pack_into("<16s16sQQIIIIIIII", data, 104, b"__text", b"__TEXT", base + 4096, 8,
                     4096, 2, 0, 0, 0x80000400, 0, 0, 0)
    struct.pack_into("<6I", data, 184, 0x2c, 24, 4096, 4096, int(encrypted), 0)
    data[4096:4104] = b"\x00\x00\x80\x52\xc0\x03\x5f\xd6"  # mov w0, #0; ret
    return bytes(data)


def ipa(path, encrypted=False):
    info = plistlib.dumps({"CFBundleExecutable": "Synthetic", "CFBundleIdentifier": "org.example.synthetic"})
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Payload/Synthetic.app/Info.plist", info)
        archive.writestr("Payload/Synthetic.app/Synthetic", synthetic_macho(encrypted))


def main():
    import binaryninja as bn
    source = Path(__file__).resolve().parents[1] / "__init__.py"
    spec = importlib.util.spec_from_file_location("unfairplay_bn_native_control", source)
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)
    transform = bn.Transform[plugin.TRANSFORM_NAME]
    old_environ = {key: os.environ.get(key) for key in (
        "UNFAIRPLAY_BINARY", "UNFAIRPLAY_BINARYNINJA_MODEL", "UNFAIRPLAY_SYNTHETIC_PLAIN")}
    try:
        with tempfile.TemporaryDirectory(prefix="unfairplay-bn-control-") as directory:
            work = Path(directory)
            plain, encrypted = work / "plain.ipa", work / "encrypted.ipa"
            ipa(plain)
            ipa(encrypted, True)
            cli = work / "synthetic-cli"
            cli.write_text("#!/usr/bin/env python3\n" + '''import json, os, pathlib, shutil, sys
args = sys.argv
output = pathlib.Path(args[args.index('--output')+1])
report = pathlib.Path(args[args.index('--report')+1])
shutil.copyfile(os.environ['UNFAIRPLAY_SYNTHETIC_PLAIN'], output)
report.write_text('{}')
print(json.dumps({'EncryptedImages': 1, 'PlaintextVerified': True}))
''')
            cli.chmod(0o700)
            model = work / "synthetic.bin"
            model.write_bytes(b"synthetic placeholder; never used with the real CLI")
            os.environ.update(UNFAIRPLAY_BINARY=str(cli), UNFAIRPLAY_BINARYNINJA_MODEL=str(model),
                              UNFAIRPLAY_SYNTHETIC_PLAIN=str(plain))
            for filename in (plain, encrypted):
                with bn.BinaryView.new(filename.read_bytes()) as raw:
                    assert transform.can_decode(raw), "IPA detection failed"
                    session = bn.TransformSession(raw, mode=bn.TransformSessionMode.TransformSessionModeInteractive)
                    context = session.root_context
                    context.set_transform_name(plugin.TRANSFORM_NAME)
                    params = {"allow-decryption": b"yes"}
                    assert not transform.decode_with_context(context, params), "Discovery must pause"
                    selected = "Payload/Synthetic.app/Synthetic"
                    assert context.available_files == [selected]
                    context.set_requested_files([selected])
                    assert transform.decode_with_context(context, params), "Extraction failed"
                    child = context.get_child(selected)
                    assert child.input.read(0, child.input.length) == synthetic_macho()
                    with bn.load(child.input, update_analysis=False) as loaded:
                        assert loaded is not None and loaded.view_type == "Mach-O"
                        assert loaded.arch.name == "aarch64"
                        assert "ret" in loaded.get_disassembly(0x100001004).lower()
            with plugin._load_ipa_view(encrypted, {"allow-decryption": b"yes"}) as loaded:
                assert loaded.view_type == "Mach-O"
                assert "ret" in loaded.get_disassembly(0x100001004).lower()
            print("PASS: native Binary Ninja container discovery, plaintext and synthetic CLI extraction, forced-transform menu loader, Mach-O loading")
    finally:
        for key, value in old_environ.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


if __name__ == "__main__":
    main()
