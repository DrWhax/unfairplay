"""UnfairPlay IPA container loader for Binary Ninja 6.0+."""

import importlib.util
import io
import os
from pathlib import Path
import shutil
import sys
import tempfile
import zipfile

import binaryninja as bn
from binaryninja import interaction


def _load_core():
    # Reuse the IDA integration's standard-library-only archive/CLI helpers.
    # Releases/installations place this helper next to this plugin; source
    # checkouts use the original file so there is a single maintained copy.
    directory = Path(__file__).resolve().parent
    candidates = (directory / "unfairplay_ipa.py", directory.parent / "ida" / "unfairplay_ipa.py")
    source = next((p for p in candidates if p.is_file()), None)
    if source is None:
        raise ImportError("Install unfairplay_ipa.py alongside the Binary Ninja plugin")
    spec = importlib.util.spec_from_file_location("_unfairplay_binaryninja_core", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


core = _load_core()
TRANSFORM_NAME = "UnfairPlayIPA"


class ViewReader(io.RawIOBase):
    """Seekable ZIP reader over a BinaryView without copying the whole IPA."""
    def __init__(self, view):
        super().__init__()
        self.view = view
        self.position = 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_CUR:
            offset += self.position
        elif whence == io.SEEK_END:
            offset += self.view.length
        elif whence != io.SEEK_SET:
            raise ValueError("Invalid seek origin")
        if offset < 0:
            raise ValueError("Negative seek")
        self.position = offset
        return offset

    def read(self, size=-1):
        available = max(0, self.view.length - self.position)
        size = available if size is None or size < 0 else min(size, available)
        if not size:
            return b""
        value = self.view.read(self.view.start + self.position, size)
        if value is None or len(value) != size:
            raise core.IPAError("Truncated IPA BinaryView")
        self.position += size
        return bytes(value)


def _on_ui(callback):
    # execute_on_main_thread_and_wait itself does not return callback results.
    if bn.is_main_thread():
        return callback()
    result, errors = [], []
    def invoke():
        try:
            result.append(callback())
        except Exception as exc:
            errors.append(exc)
    bn.execute_on_main_thread_and_wait(invoke)
    if errors:
        raise errors[0]
    return result[0]


def _notice(message):
    if bn.core_ui_enabled():
        _on_ui(lambda: interaction.show_message_box("UnfairPlay", message))
    else:
        bn.log_warn(message)


def _consent(params, key, message):
    if params.get(key) == b"yes":
        return True
    if not bn.core_ui_enabled():
        return False
    return _on_ui(lambda: interaction.show_message_box(
        "UnfairPlay", message, bn.MessageBoxButtonSet.YesNoButtonSet,
        bn.MessageBoxIcon.QuestionIcon)) == bn.MessageBoxButtonResult.YesButton


def _model_location():
    environ = dict(os.environ)
    # BN has its own override; an IDA-specific setting must not select its model.
    environ["UNFAIRPLAY_IDA_MODEL"] = environ.get("UNFAIRPLAY_BINARYNINJA_MODEL", "")
    return core.model_location(environ=environ)


def _binary_location():
    binary = os.environ.get("UNFAIRPLAY_BINARY") or shutil.which("unfairplay")
    if not binary and bn.core_ui_enabled():
        binary = _on_ui(lambda: interaction.get_open_filename_input("Locate the unfairplay executable"))
    if not binary:
        raise core.IPAError("Locate unfairplay on PATH or set UNFAIRPLAY_BINARY before starting Binary Ninja")
    return str(Path(binary).expanduser())


def _decrypt(binary, source, output, report, model):
    if not bn.core_ui_enabled():
        return core.run_decrypt(binary, source, output, report, model)
    result, errors = [], []
    def task(progress):
        try:
            result.append(core.run_decrypt(binary, source, output, report, model,
                                           lambda: not progress(0, 1)))
        except Exception as exc:
            errors.append(exc)
    completed = _on_ui(lambda: interaction.run_progress_dialog("UnfairPlay: decrypting IPA", True, task))
    if errors:
        raise errors[0]
    if not completed or not result:
        raise core.Cancelled()
    return result[0]


def _image_bytes(source, requested):
    # Validate every selected image before returning any plaintext children.
    results = []
    with zipfile.ZipFile(source) as archive:
        members = core.archive_members(archive)
        for name in requested:
            info = members.get(name)
            if info is None or info.is_dir():
                raise core.IPAError("Selected executable is missing from IPA")
            with archive.open(info) as stream:
                if core.macho_encrypted(stream, info.file_size) is not False:
                    raise core.IPAError("Selected executable is not a decrypted Mach-O")
                stream.seek(0)
                results.append((name, stream.read()))
    return results


class UnfairPlayIPA(bn.Transform):
    name = TRANSFORM_NAME
    long_name = "iOS IPA (UnfairPlay)"
    group = "Container"
    transform_type = bn.TransformType.DecodeTransform
    capabilities = (bn.TransformCapabilities.TransformSupportsContext |
                    bn.TransformCapabilities.TransformSupportsDetection)
    parameters = [bn.TransformParameter("allow-decryption", "Allow headless decryption (yes)"),
                  bn.TransformParameter("allow-unverified", "Allow unverified plaintext (yes)")]

    def can_decode(self, view):
        if view.read(view.start, 4) != b"PK\x03\x04":
            return False
        try:
            with zipfile.ZipFile(ViewReader(view)) as archive:
                core.main_executable(archive, core.archive_members(archive))
            return True
        except (OSError, ValueError, RuntimeError, core.IPAError, zipfile.BadZipFile):
            return False

    def perform_decode_with_context(self, context, params):
        try:
            view = context.input
            if view is None:
                raise core.IPAError("IPA container has no input")
            main, images, encrypted = core.inspect_ipa(ViewReader(view))
            if not context.has_available_files:
                context.set_available_files([main] + [name for name in images if name != main])
                return False
            requested = context.requested_files
            if not requested:
                return False
            if len(set(requested)) != len(requested) or any(name not in images for name in requested):
                raise core.IPAError("Requested IPA executable is missing, duplicated, or unsupported")
            if encrypted:
                if sys.platform not in ("darwin", "linux"):
                    raise core.IPAError("UnfairPlay decryption requires macOS or Linux")
                model = _model_location()
                if not core.enrollment_exists(model):
                    raise core.IPAError(core.setup_instructions().replace(
                        "UNFAIRPLAY_IDA_MODEL", "UNFAIRPLAY_BINARYNINJA_MODEL"))
                if not bn.core_ui_enabled() and params.get("allow-decryption") != b"yes":
                    raise core.Cancelled()
                binary = _binary_location()
                with tempfile.TemporaryDirectory(prefix="unfairplay-binaryninja-") as directory:
                    work = Path(directory)
                    source, output, report = work / "input.ipa", work / "decrypted.ipa", work / "report.json"
                    # Use the exact BinaryView input, including nested-container input.
                    with source.open("xb") as destination:
                        os.chmod(source, 0o600)
                        shutil.copyfileobj(ViewReader(view), destination, 1024 * 1024)
                    result = _decrypt(binary, source, output, report, model)
                    verified = result["PlaintextVerified"]
                    if not verified and not _consent(params, "allow-unverified",
                            "Pre-encryption hashes are missing for one or more images. "
                            "Plaintext is unverified. Load the selected executables anyway?"):
                        raise core.Cancelled()
                    extracted = _image_bytes(output, requested)
                message = "Pre-encryption hashes verified" if verified else "Plaintext unverified (accepted)"
            else:
                extracted = _image_bytes(ViewReader(view), requested)
                message = "Input already decrypted; plaintext authenticity not checked"
            for name, content in extracted:
                context.create_child(bn.DataBuffer(content), name, message=message)
            context.transform_result = bn.TransformResult.TransformSuccess
            return True
        except core.Cancelled:
            context.transform_result = bn.TransformResult.TransformFailure
            bn.log_info("UnfairPlay: IPA loading cancelled; no decrypted children produced")
            return False
        except (OSError, ValueError, RuntimeError, core.IPAError, zipfile.BadZipFile) as exc:
            context.transform_result = bn.TransformResult.TransformFailure
            bn.log_error("UnfairPlay: " + str(exc))
            if bn.core_ui_enabled():
                _notice("UnfairPlay: " + str(exc))
            return False


def _load_ipa_view(filename, params=None):
    """Force our transform before any generic ZIP processing can run."""
    session = bn.TransformSession(str(filename), mode=bn.TransformSessionMode.TransformSessionModeInteractive)
    context = session.root_context
    if context is None:
        raise core.IPAError("Unable to create IPA container context")
    context.set_transform_name(TRANSFORM_NAME)
    transform = bn.Transform[TRANSFORM_NAME]
    transform.decode_with_context(context, params or {})
    names = context.available_files
    if not names:
        return None  # The transform has already reported the error.
    if len(names) == 1:
        selected = names[0]
    else:
        choice = _on_ui(lambda: interaction.get_choice_input(
            "Choose an executable (main app listed first)", "UnfairPlay: open IPA", names))
        if choice is None:
            return None
        if not 0 <= choice < len(names):
            raise core.IPAError("Invalid executable selection")
        selected = names[choice]
    context.set_requested_files([selected])
    if not transform.decode_with_context(context, params or {}):
        return None
    child = context.get_child(selected)
    if child is None or child.extraction_result != bn.TransformResult.TransformSuccess:
        raise core.IPAError("IPA extraction did not produce the selected executable")
    session.set_selected_contexts(child)
    loaded = bn.load(child.input, update_analysis=False)
    if loaded is None:
        raise core.IPAError("Binary Ninja could not load this Mach-O architecture")
    if loaded.view_type != "Mach-O":
        loaded.file.close()
        raise core.IPAError("Executable did not load as Mach-O")
    return loaded


def _show_loaded_view(loaded):
    from binaryninjaui import FileContext, UIContext
    ui = UIContext.activeContext()
    if ui is None:
        raise core.IPAError("No active Binary Ninja window")
    frame = ui.openFileContext(FileContext(loaded.file, loaded, ""))
    if frame is None:
        raise core.IPAError("Unable to open decrypted executable in a tab")


def _open_ipa_path(filename):
    loaded = None
    try:
        loaded = _load_ipa_view(filename)
        if loaded is None:
            return
        _on_ui(lambda: _show_loaded_view(loaded))
        loaded.update_analysis()
    except (OSError, ValueError, RuntimeError, core.IPAError) as exc:
        if loaded is not None:
            loaded.file.close()
        _notice("UnfairPlay: " + str(exc))


def open_ipa():
    filename = _on_ui(lambda: interaction.get_open_filename_input(
        "UnfairPlay: open IPA", "iOS applications (*.ipa)"))
    if filename:
        bn.worker_enqueue(lambda: _open_ipa_path(filename), "UnfairPlay IPA loader")


UnfairPlayIPA.register()
bn.PluginCommand.register_global(
    "UnfairPlay\\Open IPA...", "Select an IPA, decrypt with a saved model, and load an executable as Mach-O", open_ipa)
