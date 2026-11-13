import io
import json
import os
from pathlib import Path
import plistlib
import stat
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import unfairplay_ipa as plugin


def macho(encrypted=False):
    data = bytearray(128)
    struct.pack_into("<8I", data, 0, 0xfeedfacf, 0x100000c, 0, 2, 1, 24, 0, 0)
    struct.pack_into("<6I", data, 32, 0x2c, 24, 64, 32, int(encrypted), 0)
    return bytes(data)


def make_ipa(filename, encrypted=False, extra=None):
    entries = {"Payload/Test.app/Info.plist": plistlib.dumps({"CFBundleExecutable": "Test"}),
               "Payload/Test.app/Test": macho(encrypted), "Payload/Test.app/resource.txt": b"hello"}
    entries.update(extra or {})
    with zipfile.ZipFile(filename, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)


class LoaderTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.directory = Path(self.workspace.name)
        self.ipa = self.directory / "synthetic.ipa"
        self.ui = types.SimpleNamespace(Choose=object, ASKBTN_YES=1, ASKBTN_NO=0, ask_yn=lambda *args: 1,
                                        warning=lambda message: None, show_wait_box=lambda *args: None,
                                        hide_wait_box=lambda: None, user_cancelled=lambda: False)

    def test_inventory_and_selected_extraction(self):
        for encrypted in (False, True):
            make_ipa(self.ipa, encrypted)
            main, images, found = plugin.inspect_ipa(self.ipa)
            self.assertEqual(found, encrypted)
            self.assertEqual(images, [main])
            if encrypted:
                with self.assertRaises(plugin.IPAError):
                    plugin.extract_image(self.ipa, main)
            else:
                path = Path(plugin.extract_image(self.ipa, main))
                self.addCleanup(path.unlink)
                self.assertEqual(path.read_bytes(), macho())
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_universal_encryption(self):
        for endian, magic, width in ((">", 0xcafebabe, 20), ("<", 0xcafebabe, 20),
                                      (">", 0xcafebabf, 32), ("<", 0xcafebabf, 32)):
            data = bytearray(512)
            struct.pack_into(endian + "II", data, 0, magic, 1)
            struct.pack_into(endian + ("IIQQII" if width == 32 else "IIIII"), data, 8,
                             0x100000c, 0, 256, 128, 8, *([0] if width == 32 else []))
            data[256:384] = macho(True)
            self.assertTrue(plugin.macho_encrypted(io.BytesIO(data), len(data)))
            data[256:260] = b"text"
            with self.assertRaises(plugin.IPAError):
                plugin.macho_encrypted(io.BytesIO(data), len(data))

    def test_bad_macho_headers(self):
        cases = []
        for offset, value in ((20, 2**32 - 1), (16, 100), (36, 4), (48, 2), (40, 200)):
            data = bytearray(macho(True))
            struct.pack_into("<I", data, offset, value)
            cases.append(data)
        cases.append(b"\xcf\xfa\xed\xfe" + b"\0" * 10)
        for data in cases:
            with self.subTest(data=data[:24]), self.assertRaises(plugin.IPAError):
                plugin.macho_encrypted(io.BytesIO(data), len(data))

    def test_bad_archives(self):
        for extra in ({"../escape": b"bad"}, {"Payload/Test.app/RESOURCE.txt": b"bad"},
                      {"Payload/Second.app/a": b"bad"}, {"Payload/Test.app/Info.plist": b"bad"},
                      {"Payload/Test.app/Test": b"not macho"}):
            make_ipa(self.ipa, extra=extra)
            with self.assertRaises(plugin.IPAError):
                plugin.inspect_ipa(self.ipa)
        make_ipa(self.ipa)
        with zipfile.ZipFile(self.ipa, "a") as archive:
            link = zipfile.ZipInfo("Payload/Test.app/link")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, "/outside")
        with self.assertRaises(plugin.IPAError):
            plugin.inspect_ipa(self.ipa)

    def test_model_discovery(self):
        self.assertEqual(plugin.model_location({}, "darwin", "/synthetic"),
                         Path("/synthetic/Library/Application Support/unfairplay/models"))
        self.assertEqual(plugin.model_location({"XDG_CONFIG_HOME": "/synthetic/config"}, "linux", "/synthetic"),
                         Path("/synthetic/config/unfairplay/models"))
        self.assertEqual(plugin.model_location({"UNFAIRPLAY_IDA_MODEL": "/explicit/model.bin", "UNFAIRPLAY_MODEL_DIR": "/other"}),
                         Path("/explicit/model.bin"))
        with self.assertRaises(plugin.IPAError):
            plugin.model_location({"XDG_CONFIG_HOME": "relative"}, "linux", "/synthetic")
        self.assertFalse(plugin.enrollment_exists(self.directory))
        (self.directory / "model.bin").write_bytes(b"synthetic, not a valid model")
        self.assertTrue(plugin.enrollment_exists(self.directory))
        self.assertTrue(plugin.enrollment_exists(self.directory / "model.bin"))

    def test_accept_file_with_linput_protocol(self):
        make_ipa(self.ipa)
        class LInput:
            def __init__(self, data): self.stream = io.BytesIO(data)
            def read(self, *args): return self.stream.read(*args)
            def seek(self, *args): return self.stream.seek(*args)
            def tell(self): return self.stream.tell()
        loader = types.SimpleNamespace(ACCEPT_ARCHIVE=0x2000, ACCEPT_FIRST=0x1000)
        with patch.dict(sys.modules, {"ida_loader": loader}):
            self.assertEqual(plugin.accept_file(LInput(self.ipa.read_bytes()), str(self.ipa))["format"], plugin.FORMAT)
            self.assertEqual(plugin.accept_file(LInput(b"bad"), "synthetic.ipa"), 0)
            self.assertEqual(plugin.accept_file(LInput(b"bad"), "synthetic.zip"), 0)

    def test_plaintext_callback(self):
        make_ipa(self.ipa)
        with patch.dict(sys.modules, {"ida_kernwin": self.ui}):
            result = plugin.process_archive(None, str(self.ipa), "", 5, plugin.FORMAT)
        self.assertEqual(result["module_name"], "Payload/Test.app/Test")
        self.assertEqual(result["neflags"], 5)
        Path(result["temp_file"]).unlink()

    def test_nested_image_chooser_defaults_to_main(self):
        make_ipa(self.ipa, extra={"Payload/Test.app/Frameworks/Library.framework/Library": macho()})
        captured = {}
        class Choose:
            CH_MODAL = 1
            def __init__(self, title, columns, **kwargs): captured.update(kwargs)
            def Show(self, modal=False):
                self.OnGetLine(0)
                self.OnGetSize()
                return self.deflt if hasattr(self, "deflt") else captured["deflt"]
        self.ui.Choose = Choose
        with patch.dict(sys.modules, {"ida_kernwin": self.ui}):
            result = plugin.process_archive(None, str(self.ipa), "", 0, plugin.FORMAT)
        self.assertEqual(result["module_name"], "Payload/Test.app/Test")
        Path(result["temp_file"]).unlink()

    def test_missing_enrollment_offers_setup_without_decrypt(self):
        make_ipa(self.ipa, True)
        warnings = []
        self.ui.warning = lambda message: warnings.append(message)
        with patch.dict(sys.modules, {"ida_kernwin": self.ui}), patch.object(plugin, "model_location", return_value=self.directory), patch.object(plugin, "run_decrypt") as decrypt:
            self.assertEqual(plugin.process_archive(None, str(self.ipa), "", 0, plugin.FORMAT), "")
            decrypt.assert_not_called()
        self.assertEqual(warnings, [plugin.setup_instructions()])

    def test_user_decline_without_decrypt(self):
        make_ipa(self.ipa, True)
        self.ui.ask_yn = lambda *args: 0
        with patch.dict(sys.modules, {"ida_kernwin": self.ui}), patch.object(plugin, "enrollment_exists", return_value=True), patch.object(plugin, "run_decrypt") as decrypt:
            self.assertEqual(plugin.process_archive(None, str(self.ipa), "", 0, plugin.FORMAT), "")
            decrypt.assert_not_called()

    def test_encrypted_callback_cleans_workspace(self):
        make_ipa(self.ipa, True)
        saved = []
        def decrypt(binary, source, output, report, model, cancelled):
            saved.append(output.parent)
            make_ipa(output)
            report.write_text("synthetic")
            return {"PlaintextVerified": True}
        with patch.dict(sys.modules, {"ida_kernwin": self.ui}), patch.dict(os.environ, {"UNFAIRPLAY_BINARY": "synthetic-unfairplay"}), patch.object(plugin, "enrollment_exists", return_value=True), patch.object(plugin, "run_decrypt", side_effect=decrypt):
            result = plugin.process_archive(None, str(self.ipa), "", 0, plugin.FORMAT)
        self.assertFalse(saved[0].exists())
        self.assertEqual(Path(result["temp_file"]).read_bytes(), macho())
        Path(result["temp_file"]).unlink()
        self.assertTrue(plugin.inspect_ipa(self.ipa)[2])

    def test_unverified_output_requires_confirmation(self):
        make_ipa(self.ipa, True)
        answers = iter([1, 0])
        self.ui.ask_yn = lambda *args: next(answers)
        def decrypt(binary, source, output, *args):
            make_ipa(output)
            return {"PlaintextVerified": False}
        with patch.dict(sys.modules, {"ida_kernwin": self.ui}), patch.dict(os.environ, {"UNFAIRPLAY_BINARY": "synthetic"}), patch.object(plugin, "enrollment_exists", return_value=True), patch.object(plugin, "run_decrypt", side_effect=decrypt):
            self.assertEqual(plugin.process_archive(None, str(self.ipa), "", 0, plugin.FORMAT), "")

    def test_saved_member_selection_and_ambiguity(self):
        make_ipa(self.ipa, extra={"Payload/Test.app/PlugIns/Widget.appex/Test": macho()})
        with patch.dict(sys.modules, {"ida_kernwin": self.ui}):
            result = plugin.process_archive(None, str(self.ipa), "Test", 0, plugin.FORMAT)
            self.assertIn("ambiguous", result)
            result = plugin.process_archive(None, str(self.ipa), "Payload/Test.app/Test", 0, plugin.FORMAT)
            Path(result["temp_file"]).unlink()

    def test_cli_errors_and_incomplete_results_fail_closed(self):
        output = self.directory / "output.ipa"
        output.write_bytes(b"synthetic")
        for status, payload in ((1, b""), (0, b"not json"), (0, b"{}"),
                                (0, b'{"EncryptedImages":1,"PlaintextVerified":1}')):
            class Process:
                def __init__(self, args, **kwargs):
                    kwargs["stdout"].write(payload)
                    kwargs["stderr"].write(b"synthetic CLI failure")
                def wait(self, **kwargs): return status
                def poll(self): return status
            with self.subTest(status=status, payload=payload), patch.object(plugin.subprocess, "Popen", side_effect=Process):
                with self.assertRaises(plugin.IPAError):
                    plugin.run_decrypt("synthetic", self.ipa, output, self.directory / "report", self.directory)

    def test_subprocess_contract(self):
        output, report = self.directory / "out.ipa", self.directory / "out.json"
        output.write_bytes(b"synthetic")
        class Process:
            def __init__(self, args, **kwargs):
                self.args, self.kwargs = args, kwargs
                kwargs["stdout"].write(json.dumps({"EncryptedImages": 1, "PlaintextVerified": False}).encode())
            def wait(self, **kwargs): return 0
            def poll(self): return 0
        with patch.object(plugin.subprocess, "Popen", side_effect=Process) as popen:
            result = plugin.run_decrypt("/synthetic/tool with spaces", "/synthetic/input with spaces.ipa", output, report, "/synthetic/model.bin")
        self.assertFalse(result["PlaintextVerified"])
        args, kwargs = popen.call_args
        self.assertIn("--strip-account-data", args[0])
        self.assertEqual(args[0][0], "/synthetic/tool with spaces")
        self.assertFalse(kwargs["shell"])

    def test_subprocess_cancellation_terminates_and_reaps(self):
        process = types.SimpleNamespace(wait=lambda **kwargs: 0, poll=lambda: None, terminate=lambda: None)
        with patch.object(plugin.subprocess, "Popen", return_value=process), patch.object(process, "terminate") as terminate:
            with self.assertRaises(plugin.Cancelled):
                plugin.run_decrypt("synthetic", self.ipa, self.directory / "out", self.directory / "report", self.directory, lambda: True)
            terminate.assert_called_once()


if __name__ == "__main__":
    unittest.main()
