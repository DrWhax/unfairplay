"""Opt-in synthetic integration control; requires IDADIR and IDA 9.4 idapro.

Uses a temporary loader directory over the licensed user profile and a fake
CLI, never private enrollment. No plugin is installed in the user profile.
"""
import os
from pathlib import Path
import shutil
import tempfile


def main():
    if not os.environ.get("IDADIR"):
        raise SystemExit("Set IDADIR to the IDA 9.4 installation directory first")
    with tempfile.TemporaryDirectory(prefix="unfairplay-ida94-control-") as work:
        directory = Path(work)
        user = directory / "ida-user"
        (user / "loaders").mkdir(parents=True)
        source = Path(__file__).resolve().parents[1] / "unfairplay_ipa.py"
        shutil.copyfile(source, user / "loaders" / source.name)
        os.environ["IDAUSR"] = str(user) + os.pathsep + os.environ.get("IDAUSR", str(Path.home() / ".idapro"))
        os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
        import idapro
        import ida_ida
        import ida_kernwin
        import ida_loader
        from test_unfairplay_ipa import make_ipa
        assert idapro.get_library_version()[:2] == (9, 4), "This control targets IDA 9.4"
        plain, encrypted = directory / "plain.ipa", directory / "encrypted.ipa"
        make_ipa(plain)
        make_ipa(encrypted, True)
        assert idapro.open_database(str(plain), False) == 0, "IPA loader discovery failed"
        assert ida_ida.inf_get_procname() == "ARM"
        assert "Mach-O" in ida_loader.get_file_type_name()
        idapro.close_database(False)

        # Use IDA's actual warning() wrapper on the missing-enrollment path.
        import unfairplay_ipa
        os.environ["UNFAIRPLAY_IDA_MODEL"] = str(directory / "missing-model")
        assert unfairplay_ipa.process_archive(None, str(encrypted), "", 0, unfairplay_ipa.FORMAT) == ""

        # Exercise the offered-decryption path without genuine FairPlay state.
        # The fake CLI copies the known synthetic plaintext fixture.
        cli = directory / "synthetic-unfairplay"
        cli.write_text("#!/usr/bin/env python3\n" + '''import json, os, pathlib, shutil, sys
args = sys.argv
output = pathlib.Path(args[args.index('--output')+1])
report = pathlib.Path(args[args.index('--report')+1])
shutil.copyfile(os.environ['SYNTHETIC_PLAIN_IPA'], output)
report.write_text('{}')
pathlib.Path(os.environ['SYNTHETIC_WORK_RECORD']).write_text(str(output.parent))
print(json.dumps({'EncryptedImages': 1, 'PlaintextVerified': True}))
''')
        cli.chmod(0o700)
        model = directory / "synthetic.bin"
        model.write_bytes(b"synthetic placeholder; never passed to real UnfairPlay")
        record = directory / "work-record"
        os.environ.update(UNFAIRPLAY_BINARY=str(cli), UNFAIRPLAY_IDA_MODEL=str(model),
                          SYNTHETIC_PLAIN_IPA=str(plain), SYNTHETIC_WORK_RECORD=str(record))
        ida_kernwin.ask_yn = lambda *args: ida_kernwin.ASKBTN_YES
        assert idapro.open_database(str(encrypted), False) == 0, "Encrypted IPA handoff failed"
        assert ida_ida.inf_get_procname() == "ARM"
        assert "Mach-O" in ida_loader.get_file_type_name()
        assert record.is_file(), "UnfairPlay subprocess was not invoked"
        assert not Path(record.read_text()).exists(), "Decryption workspace was retained"
        idapro.close_database(False)
        print("PASS: IDA 9.4 archive discovery, plaintext Mach-O handoff, missing-enrollment warning, synthetic CLI handoff, cleanup")


if __name__ == "__main__":
    main()
