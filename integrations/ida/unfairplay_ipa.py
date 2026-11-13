"""UnfairPlay IPA archive loader for IDA Pro 9.4 (Python 3, standard library only).

Install this file in IDAUSR/loaders, not plugins: decryption must happen before
IDA's Mach-O loader starts. No enrollment or application code runs in Python.
"""

import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile

FORMAT = "iOS IPA (UnfairPlay)"
MAX_COMMAND_BYTES = 1024 * 1024


class IPAError(Exception):
    pass


class Cancelled(Exception):
    pass


def safe_member(name):
    stripped = name.rstrip("/")
    if (not stripped or "\\" in stripped or ":" in stripped or "\0" in stripped
            or stripped.startswith("/") or str(PurePosixPath(stripped)) != stripped
            or ".." in PurePosixPath(stripped).parts):
        raise IPAError("Unsafe IPA archive member")
    return stripped


def archive_members(archive):
    members, folded = {}, set()
    for info in archive.infolist():
        if "\0" in info.orig_filename:
            raise IPAError("NUL in IPA archive member")
        name = safe_member(info.filename)
        if name.casefold() in folded:
            raise IPAError("Duplicate or case-colliding IPA archive members")
        folded.add(name.casefold())
        kind = stat.S_IFMT(info.external_attr >> 16)
        if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise IPAError("IPA symlinks and special files are unsupported")
        members[name] = info
    return members


def main_executable(archive, members):
    roots = {"/".join(name.split("/")[:2]) for name in members
             if name.startswith("Payload/") and len(name.split("/")) >= 2
             and name.split("/")[1].endswith(".app")}
    if len(roots) != 1:
        raise IPAError("IPA must contain exactly one top-level Payload app")
    root = roots.pop()
    info = members.get(root + "/Info.plist")
    if info is None or info.file_size > 4 * 1024 * 1024:
        raise IPAError("Missing or oversized app Info.plist")
    try:
        metadata = plistlib.loads(archive.read(info))
        executable = metadata.get("CFBundleExecutable")
    except (ValueError, TypeError, AttributeError, plistlib.InvalidFileException) as exc:
        raise IPAError("Invalid app Info.plist") from exc
    if (not isinstance(executable, str) or not executable or executable in (".", "..")
            or any(c in executable for c in "/\\:\0")):
        raise IPAError("Invalid CFBundleExecutable")
    member = root + "/" + executable
    if member not in members or members[member].is_dir():
        raise IPAError("App executable is missing")
    return member


def _read_at(stream, offset, count):
    stream.seek(offset)
    data = stream.read(count)
    if len(data) != count:
        raise IPAError("Truncated Mach-O")
    return data


def macho_encrypted(stream, total, base=0, extent=None, nested=False):
    """Read bounded headers only; UnfairPlay remains the decryption authority."""
    extent = total if extent is None else extent
    if extent < 4:
        return None
    magic = _read_at(stream, base, 4)
    fat = {b"\xca\xfe\xba\xbe": (">", 20), b"\xbe\xba\xfe\xca": ("<", 20),
           b"\xca\xfe\xba\xbf": (">", 32), b"\xbf\xba\xfe\xca": ("<", 32)}
    if magic in fat:
        if nested or extent < 8:
            raise IPAError("Invalid universal Mach-O")
        endian, width = fat[magic]
        count = struct.unpack(endian + "I", _read_at(stream, base + 4, 4))[0]
        if not 1 <= count <= 32 or 8 + count * width > extent:
            raise IPAError("Invalid universal Mach-O architecture count")
        table = _read_at(stream, base + 8, count * width)
        ranges, encrypted = [], False
        for index in range(count):
            entry = table[index * width:(index + 1) * width]
            cpu, subtype = struct.unpack_from(endian + "II", entry)
            offset, size, align = struct.unpack_from(endian + ("QQI" if width == 32 else "III"), entry, 8)
            if (size < 28 or offset < 8 + count * width or offset > extent or size > extent - offset
                    or align > 63 or offset % (1 << align)
                    or any(offset < end and start < offset + size for start, end in ranges)):
                raise IPAError("Invalid universal Mach-O slice bounds")
            ranges.append((offset, offset + size))
            header = _read_at(stream, base + offset, 12)
            if header[:4] not in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") or struct.unpack_from("<II", header, 4) != (cpu, subtype):
                raise IPAError("Universal Mach-O slice does not match architecture table")
            value = macho_encrypted(stream, total, base + offset, size, True)
            if value is None:
                raise IPAError("Universal Mach-O contains an unknown slice")
            encrypted = encrypted or value
        return encrypted
    if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        raise IPAError("Big-endian Mach-O is unsupported")
    if magic not in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return None
    header_size = 32 if magic == b"\xcf\xfa\xed\xfe" else 28
    if extent < header_size:
        raise IPAError("Truncated Mach-O header")
    header = _read_at(stream, base, header_size)
    count, size = struct.unpack_from("<II", header, 16)
    if size > MAX_COMMAND_BYTES or size > extent - header_size or count > size // 8:
        raise IPAError("Invalid Mach-O load-command bounds")
    commands = _read_at(stream, base + header_size, size)
    cursor, encryption, encrypted = 0, False, False
    for _ in range(count):
        if cursor + 8 > size:
            raise IPAError("Truncated Mach-O load command")
        kind, length = struct.unpack_from("<II", commands, cursor)
        if length < 8 or length > size - cursor:
            raise IPAError("Invalid Mach-O load command size")
        if kind in (0x21, 0x2c):
            if length < (24 if kind == 0x2c else 20) or encryption:
                raise IPAError("Invalid Mach-O encryption command")
            offset, cryptsize, cryptid = struct.unpack_from("<III", commands, cursor + 8)
            if cryptid not in (0, 1) or offset > extent or cryptsize > extent - offset:
                raise IPAError("Unsupported or malformed Mach-O encryption range")
            encryption, encrypted = True, cryptid != 0
        cursor += length
    if cursor != size:
        raise IPAError("Mach-O commands do not fill header")
    return encrypted


def inspect_ipa(filename):
    with zipfile.ZipFile(filename) as archive:
        members = archive_members(archive)
        main = main_executable(archive, members)
        images, encrypted = [], False
        for name, info in members.items():
            if info.is_dir() or not name.startswith("Payload/"):
                continue
            with archive.open(info) as stream:
                value = macho_encrypted(stream, info.file_size)
            if value is not None:
                images.append(name)
                encrypted = encrypted or value
        if main not in images:
            raise IPAError("Main executable is not a supported Mach-O")
        return main, sorted(images), encrypted


def model_location(environ=None, platform=None, home=None):
    environ = os.environ if environ is None else environ
    platform = sys.platform if platform is None else platform
    home = Path.home() if home is None else Path(home)
    explicit = environ.get("UNFAIRPLAY_IDA_MODEL") or environ.get("UNFAIRPLAY_MODEL_DIR")
    if explicit:
        return Path(explicit).expanduser().absolute()
    if platform == "darwin":
        base = home / "Library" / "Application Support"
    elif platform == "win32":
        if not environ.get("APPDATA"):
            raise IPAError("APPDATA is unset")
        base = Path(environ["APPDATA"])
    else:
        base = Path(environ.get("XDG_CONFIG_HOME") or home / ".config")
        if not base.is_absolute():
            raise IPAError("XDG_CONFIG_HOME must be absolute")
    return base / "unfairplay" / "models"


def enrollment_exists(location):
    if location.is_file():
        return True
    return location.is_dir() and any(p.is_file() and p.suffix.lower() == ".bin" for p in location.iterdir())


def run_decrypt(binary, source, output, report, model, cancelled=lambda: False):
    args = [str(binary), "decrypt", "--input", str(source), "--output", str(output),
            "--report", str(report), "--model", str(model), "--strip-account-data"]
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, shell=False)
        try:
            while True:
                if cancelled():
                    raise Cancelled()
                try:
                    code = process.wait(timeout=0.1)
                    break
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        if code:
            stderr.seek(0, os.SEEK_END)
            stderr.seek(max(0, stderr.tell() - 4096))
            raise IPAError("UnfairPlay decryption failed:\n" + stderr.read().decode("utf-8", errors="replace"))
        stdout.seek(0)
        try:
            result = json.load(stdout)
        except (ValueError, UnicodeError) as exc:
            raise IPAError("UnfairPlay returned invalid JSON") from exc
        if (not isinstance(result, dict) or type(result.get("EncryptedImages")) is not int
                or result["EncryptedImages"] < 1 or not output.is_file()
                or type(result.get("PlaintextVerified")) is not bool):
            raise IPAError("UnfairPlay returned an incomplete decryption result")
        return result


def extract_image(filename, member):
    """Extract only the selected, decrypted image. IDA owns the returned file."""
    temporary = None
    try:
        with zipfile.ZipFile(filename) as archive:
            members = archive_members(archive)
            info = members.get(member)
            if info is None or info.is_dir():
                raise IPAError("Selected executable is missing from output IPA")
            with archive.open(info) as source:
                if macho_encrypted(source, info.file_size) is not False:
                    raise IPAError("Selected executable is not a decrypted Mach-O")
                source.seek(0)
                fd, temporary = tempfile.mkstemp(prefix="unfairplay-ida-", suffix=".macho")
                with os.fdopen(fd, "wb") as destination:
                    shutil.copyfileobj(source, destination)
        return temporary
    except BaseException:
        if temporary is not None:
            os.unlink(temporary)
        raise


def setup_instructions(binary="unfairplay"):
    return ("No saved UnfairPlay enrollment model was found.\n\n"
            "On an enrolled Mac, sign in to the native Mac App Store, install an iOS app "
            "and open it once. Then run once in a terminal:\n\n"
            "sudo " + str(binary) + " setup --app /Applications/App.app --ipa App.ipa\n\n"
            "Use an encrypted IPA matching that installed app and Store account. "
            "Reopen this IPA after setup. Other IPAs must belong to the same enrollment.\n\n"
            "For an existing model elsewhere, set UNFAIRPLAY_IDA_MODEL to its file or directory. "
            "On Linux, securely copy a model recovered on the enrolled Mac. "
            "Windows decryption is not currently supported.")


class LoaderInput:
    # IDA linput_t has read/seek/tell, but not Python's seekable() method.
    def __init__(self, li):
        self.li = li

    def read(self, size=-1):
        return self.li.read(size) if size >= 0 else self.li.read()

    def seek(self, offset, whence=0):
        return self.li.seek(offset, whence)

    def tell(self):
        return self.li.tell()

    def seekable(self):
        return True


def accept_file(li, filename):
    if not filename.lower().endswith(".ipa"):
        return 0
    try:
        import ida_loader
        li.seek(0)
        with zipfile.ZipFile(LoaderInput(li)) as archive:
            main_executable(archive, archive_members(archive))
        return {"format": FORMAT, "options": 1 | ida_loader.ACCEPT_ARCHIVE | ida_loader.ACCEPT_FIRST}
    except (OSError, ValueError, IPAError, zipfile.BadZipFile, RuntimeError):
        return 0


def process_archive(li, archive, defmember, neflags, formatname):
    import ida_kernwin as ui

    try:
        if sys.platform == "win32":
            raise IPAError("UnfairPlay decryption currently requires macOS or Linux.")
        main, images, encrypted = inspect_ipa(archive)
        if defmember:
            matches = [name for name in images if name == defmember]
            if not matches:
                matches = [name for name in images if PurePosixPath(name).name == Path(defmember).name]
            if len(matches) != 1:
                raise IPAError("Saved archive member is missing or ambiguous; reopen the IPA and choose an executable.")
            selected = matches[0]
        else:
            class ImageChooser(ui.Choose):
                def __init__(self):
                    super().__init__("UnfairPlay: select executable", [["IPA member", 100]], flags=ui.Choose.CH_MODAL, deflt=images.index(main))

                def OnGetSize(self):
                    return len(images)

                def OnGetLine(self, index):
                    return [images[index]]

            if len(images) == 1:
                selected = main
            else:
                index = ImageChooser().Show(True)
                if index < 0:
                    return ""
                selected = images[index]
        if not encrypted:
            workfile = extract_image(archive, selected)
        else:
            model = model_location()
            if not enrollment_exists(model):
                ui.warning(setup_instructions())
                return ""
            if ui.ask_yn(ui.ASKBTN_YES, "This IPA contains encrypted Mach-O code.\n"
                         "Decrypt with the saved UnfairPlay enrollment and load the selected executable?\n\n"
                         "The input IPA stays unchanged. Temporary decrypted IPA and report files are deleted; "
                         "IDA retains the selected plaintext executable and database.") != ui.ASKBTN_YES:
                return ""
            binary = os.environ.get("UNFAIRPLAY_BINARY") or shutil.which("unfairplay")
            if not binary:
                binary = ui.ask_file(False, "*", "Locate the unfairplay command-line executable")
            if not binary:
                return ""
            ui.show_wait_box("UnfairPlay: decrypting IPA...\nCancel stops decryption.")
            waiting = True
            try:
                with tempfile.TemporaryDirectory(prefix="unfairplay-ida-work-") as directory:
                    output, report = Path(directory) / "decrypted.ipa", Path(directory) / "report.json"
                    result = run_decrypt(binary, archive, output, report, model, ui.user_cancelled)
                    ui.hide_wait_box()
                    waiting = False
                    if not result["PlaintextVerified"]:
                        if ui.ask_yn(ui.ASKBTN_NO, "Decryption completed, but pre-encryption hashes are missing for "
                                     "one or more images. Plaintext is unverified.\nLoad the selected executable anyway?") != ui.ASKBTN_YES:
                            return ""
                    workfile = extract_image(output, selected)
            finally:
                if waiting:
                    ui.hide_wait_box()
        # Use the full archive member so reopening an IDB can identify nested
        # executables without guessing between duplicate basenames.
        return {"temp_file": workfile, "module_name": selected, "neflags": neflags}
    except Cancelled:
        return ""
    except (OSError, ValueError, IPAError, zipfile.BadZipFile, RuntimeError) as exc:
        return "UnfairPlay: " + str(exc)
