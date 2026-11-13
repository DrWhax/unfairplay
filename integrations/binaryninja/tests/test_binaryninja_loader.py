import enum
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ida" / "tests"))
from test_unfairplay_ipa import make_ipa, macho


class Result(enum.IntEnum):
    TransformSuccess = 0
    TransformFailure = 2


class View:
    def __init__(self, data, start=0):
        self.data, self.start, self.length = data, start, len(data)
    def read(self, offset, length):
        return self.data[offset - self.start:offset - self.start + length]


class Context:
    def __init__(self, data):
        self.input = View(data)
        self.available_files, self.requested_files, self.children = [], [], []
        self.transform_result = None
    @property
    def has_available_files(self): return bool(self.available_files)
    def set_available_files(self, files): self.available_files = files
    def create_child(self, data, filename, **kwargs): self.children.append((filename, data, kwargs))


class Transform:
    registry = {}
    def decode_with_context(self, context, params):
        return self.perform_decode_with_context(context, params)
    @classmethod
    def __class_getitem__(cls, name): return cls.registry[name]
    @classmethod
    def register(cls): Transform.registry[cls.name] = cls()


def load_plugin():
    bn = types.ModuleType("binaryninja")
    bn.Transform = Transform
    bn.TransformType = types.SimpleNamespace(DecodeTransform=3)
    bn.TransformCapabilities = types.SimpleNamespace(TransformSupportsContext=2, TransformSupportsDetection=1)
    bn.TransformParameter = lambda *args: args
    bn.TransformResult = Result
    bn.TransformSessionMode = types.SimpleNamespace(TransformSessionModeInteractive=2)
    bn.PluginCommand = types.SimpleNamespace(register_global=Mock())
    bn.DataBuffer = bytes
    bn.core_ui_enabled = lambda: False
    bn.is_main_thread = lambda: True
    bn.MessageBoxButtonSet = types.SimpleNamespace(YesNoButtonSet=1)
    bn.MessageBoxIcon = types.SimpleNamespace(QuestionIcon=1)
    bn.MessageBoxButtonResult = types.SimpleNamespace(YesButton=1, NoButton=0)
    bn.log_warn = bn.log_error = bn.log_info = lambda message: None
    bn.interaction = types.SimpleNamespace(show_message_box=lambda *args: 1)
    path = Path(__file__).resolve().parents[1] / "__init__.py"
    spec = importlib.util.spec_from_file_location("unfairplay_bn_test", path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"binaryninja": bn}):
        spec.loader.exec_module(module)
    return module, bn


plugin, bn = load_plugin()


class BinaryNinjaLoaderTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.directory = Path(work.name)
        self.ipa = self.directory / "synthetic.ipa"
        self.transform = plugin.UnfairPlayIPA()

    def context(self, encrypted=False, extra=None):
        make_ipa(self.ipa, encrypted, extra)
        ctx = Context(self.ipa.read_bytes())
        self.assertFalse(self.transform.perform_decode_with_context(ctx, {}))
        ctx.requested_files = [ctx.available_files[0]]
        return ctx

    def test_view_reader_seeks_without_whole_archive_copy(self):
        reader = plugin.ViewReader(View(b"abcdef", 0x1000))
        self.assertEqual(reader.read(2), b"ab")
        reader.seek(-2, io.SEEK_END)
        self.assertEqual(reader.read(), b"ef")
        reader.seek(1)
        reader.seek(2, io.SEEK_CUR)
        self.assertEqual(reader.read(1), b"d")
        with self.assertRaises(ValueError): reader.seek(-1)
        with self.assertRaises(ValueError): reader.seek(0, 99)

    def test_detection_has_no_decryption_or_model_side_effects(self):
        make_ipa(self.ipa, True)
        with patch.object(plugin.core, "run_decrypt") as decrypt, patch.object(plugin.core, "model_location") as model:
            self.assertTrue(self.transform.can_decode(View(self.ipa.read_bytes())))
            self.assertFalse(self.transform.can_decode(View(b"text")))
            self.assertFalse(self.transform.can_decode(View(b"PK\x03\x04broken")))
            decrypt.assert_not_called()
            model.assert_not_called()

    def test_discovery_main_first_without_decryption(self):
        ctx = self.context(True, {"Payload/Test.app/Frameworks/Library.framework/Library": macho()})
        self.assertEqual(ctx.available_files[0], "Payload/Test.app/Test")
        self.assertEqual(len(ctx.available_files), 2)
        self.assertFalse(ctx.children)

    def test_plaintext_extracts_native_macho_child(self):
        ctx = self.context()
        self.assertTrue(self.transform.perform_decode_with_context(ctx, {}))
        self.assertEqual(ctx.children[0][1], macho())
        self.assertIn("authenticity not checked", ctx.children[0][2]["message"])
        self.assertEqual(ctx.transform_result, Result.TransformSuccess)

    def test_requested_member_must_be_executable(self):
        for names in (["../escape"], ["Payload/Test.app/resource.txt"], ["Payload/Test.app/Test"] * 2):
            ctx = self.context()
            ctx.requested_files = names
            self.assertFalse(self.transform.perform_decode_with_context(ctx, {}))
            self.assertFalse(ctx.children)
            self.assertEqual(ctx.transform_result, Result.TransformFailure)

    def test_encrypted_headless_requires_explicit_opt_in(self):
        ctx = self.context(True)
        with patch.object(plugin.core, "enrollment_exists", return_value=True), patch.object(plugin.core, "run_decrypt") as decrypt:
            self.assertFalse(self.transform.perform_decode_with_context(ctx, {}))
            decrypt.assert_not_called()
        self.assertFalse(ctx.children)

    def test_missing_model_does_not_decrypt(self):
        ctx = self.context(True)
        notices = []
        with patch.object(plugin.core, "enrollment_exists", return_value=False), patch.object(bn, "log_error", side_effect=notices.append), patch.object(plugin.core, "run_decrypt") as decrypt:
            self.assertFalse(self.transform.perform_decode_with_context(ctx, {"allow-decryption": b"yes"}))
            decrypt.assert_not_called()
        self.assertIn("UNFAIRPLAY_BINARYNINJA_MODEL", notices[0])
        self.assertNotIn("UNFAIRPLAY_IDA_MODEL", notices[0])

    def test_model_override_is_separate_from_ida(self):
        with patch.dict(os.environ, {"UNFAIRPLAY_IDA_MODEL": "/ida/model", "UNFAIRPLAY_BINARYNINJA_MODEL": "/bn/model"}):
            self.assertEqual(plugin._model_location(), Path("/bn/model"))
        with patch.dict(os.environ, {"UNFAIRPLAY_IDA_MODEL": "/ida/model", "UNFAIRPLAY_BINARYNINJA_MODEL": "", "UNFAIRPLAY_MODEL_DIR": "/shared/models"}):
            self.assertEqual(plugin._model_location(), Path("/shared/models"))

    def decrypt_stub(self, verified=True, output_encrypted=False, failure=None):
        def run(binary, source, output, report, model, *args):
            self.work = output.parent
            self.assertTrue(plugin.core.inspect_ipa(source)[2])
            self.assertEqual(source.stat().st_mode & 0o777, 0o600)
            if failure: raise failure
            make_ipa(output, output_encrypted)
            report.write_text("synthetic")
            return {"PlaintextVerified": verified}
        return run

    def run_encrypted(self, ctx, decrypt, params=None):
        with patch.object(plugin.core, "enrollment_exists", return_value=True), patch.object(plugin, "_binary_location", return_value="synthetic"), patch.object(plugin.core, "run_decrypt", side_effect=decrypt):
            return self.transform.perform_decode_with_context(ctx, params or {"allow-decryption": b"yes"})

    def test_decryption_and_cleanup(self):
        ctx = self.context(True)
        self.assertTrue(self.run_encrypted(ctx, self.decrypt_stub()))
        self.assertEqual(ctx.children[0][1], macho())
        self.assertIn("hashes verified", ctx.children[0][2]["message"])
        self.assertFalse(self.work.exists())
        self.assertTrue(plugin.core.inspect_ipa(self.ipa)[2])

    def test_unverified_headless_plaintext_requires_separate_opt_in(self):
        ctx = self.context(True)
        self.assertFalse(self.run_encrypted(ctx, self.decrypt_stub(False)))
        self.assertFalse(ctx.children)
        self.assertFalse(self.work.exists())
        ctx = self.context(True)
        self.assertTrue(self.run_encrypted(ctx, self.decrypt_stub(False), {"allow-decryption": b"yes", "allow-unverified": b"yes"}))
        self.assertIn("unverified (accepted)", ctx.children[0][2]["message"])

    def test_failed_or_cancelled_decryption_never_produces_children(self):
        for error in (plugin.core.Cancelled(), plugin.core.IPAError("synthetic failure")):
            ctx = self.context(True)
            self.assertFalse(self.run_encrypted(ctx, self.decrypt_stub(failure=error)))
            self.assertFalse(ctx.children)
            self.assertFalse(self.work.exists())

    def test_still_encrypted_output_is_rejected(self):
        ctx = self.context(True)
        self.assertFalse(self.run_encrypted(ctx, self.decrypt_stub(output_encrypted=True)))
        self.assertFalse(ctx.children)
        self.assertFalse(self.work.exists())

    def test_gui_decrypts_without_enrollment_confirmation(self):
        ctx = self.context(True)
        with patch.object(bn, "core_ui_enabled", return_value=True), patch.object(bn.interaction, "show_message_box") as prompt, patch.object(plugin.core, "enrollment_exists", return_value=True), patch.object(plugin, "_binary_location", return_value="synthetic"), patch.object(plugin, "_decrypt", side_effect=self.decrypt_stub()) as decrypt:
            self.assertTrue(self.transform.perform_decode_with_context(ctx, {}))
            decrypt.assert_called_once()
            prompt.assert_not_called()
        self.assertEqual(ctx.children[0][1], macho())
        self.assertFalse(self.work.exists())

    def test_gui_still_confirms_unverified_plaintext(self):
        ctx = self.context(True)
        with patch.object(bn, "core_ui_enabled", return_value=True), patch.object(bn.interaction, "show_message_box", return_value=0) as prompt, patch.object(plugin.core, "enrollment_exists", return_value=True), patch.object(plugin, "_binary_location", return_value="synthetic"), patch.object(plugin, "_decrypt", side_effect=self.decrypt_stub(False)):
            self.assertFalse(self.transform.perform_decode_with_context(ctx, {}))
            prompt.assert_called_once()
            self.assertIn("Plaintext is unverified", prompt.call_args.args[1])
        self.assertFalse(ctx.children)
        self.assertFalse(self.work.exists())

    def test_ui_result_is_marshaled_back_from_main_thread(self):
        with patch.object(bn, "is_main_thread", return_value=False), patch.object(bn, "execute_on_main_thread_and_wait", create=True, side_effect=lambda f: f()):
            self.assertEqual(plugin._on_ui(lambda: 42), 42)
            with self.assertRaises(ValueError):
                plugin._on_ui(lambda: (_ for _ in ()).throw(ValueError("synthetic")))

    def test_progress_cancellation_reaches_subprocess(self):
        def progress_dialog(title, cancel, task):
            task(lambda current, total: False)
            return False
        def decrypt(*args):
            self.assertTrue(args[-1]())
            raise plugin.core.Cancelled()
        with patch.object(bn, "core_ui_enabled", return_value=True), patch.object(bn.interaction, "run_progress_dialog", create=True, side_effect=progress_dialog), patch.object(plugin.core, "run_decrypt", side_effect=decrypt):
            with self.assertRaises(plugin.core.Cancelled):
                plugin._decrypt("synthetic", "input", "output", "report", "model")

    def test_global_menu_command_registered(self):
        args = bn.PluginCommand.register_global.call_args.args
        self.assertEqual(args[0], "UnfairPlay\\Open IPA...")
        self.assertIs(args[2], plugin.open_ipa)

    def menu_session(self):
        make_ipa(self.ipa)
        ctx = Context(self.ipa.read_bytes())
        ctx.set_transform_name = Mock()
        ctx.set_requested_files = lambda names: setattr(ctx, "requested_files", names)
        ctx.get_child = lambda name: types.SimpleNamespace(input=View(ctx.children[0][1]), extraction_result=Result.TransformSuccess)
        session = types.SimpleNamespace(root_context=ctx, set_selected_contexts=Mock())
        return ctx, session

    def test_menu_load_forces_transform_and_native_macho(self):
        ctx, session = self.menu_session()
        loaded = types.SimpleNamespace(view_type="Mach-O", file=types.SimpleNamespace(close=Mock()))
        with patch.object(bn, "TransformSession", create=True, return_value=session), patch.object(bn, "load", create=True, return_value=loaded) as load:
            self.assertIs(plugin._load_ipa_view(self.ipa), loaded)
        ctx.set_transform_name.assert_called_once_with("UnfairPlayIPA")
        self.assertEqual(ctx.requested_files, ["Payload/Test.app/Test"])
        session.set_selected_contexts.assert_called_once()
        self.assertEqual(load.call_args.kwargs, {"update_analysis": False})

    def test_menu_load_does_not_fall_back_to_raw(self):
        ctx, session = self.menu_session()
        close = Mock()
        loaded = types.SimpleNamespace(view_type="Raw", file=types.SimpleNamespace(close=close))
        with patch.object(bn, "TransformSession", create=True, return_value=session), patch.object(bn, "load", create=True, return_value=loaded):
            with self.assertRaises(plugin.core.IPAError): plugin._load_ipa_view(self.ipa)
        close.assert_called_once()

    def test_cancelled_file_picker_does_not_start_worker(self):
        with patch.object(bn.interaction, "get_open_filename_input", create=True, return_value=None), patch.object(bn, "worker_enqueue", create=True) as worker:
            plugin.open_ipa()
            worker.assert_not_called()

    def test_file_picker_starts_background_loader(self):
        with patch.object(bn.interaction, "get_open_filename_input", create=True, return_value=str(self.ipa)), patch.object(bn, "worker_enqueue", create=True) as worker, patch.object(plugin, "_open_ipa_path") as open_path:
            plugin.open_ipa()
            worker.call_args.args[0]()
            open_path.assert_called_once_with(str(self.ipa))


if __name__ == "__main__":
    unittest.main()
