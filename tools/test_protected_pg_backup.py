"""RC30-RV-01 controls use synthetic bytes only; no database or network."""
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("protected_backup", Path(__file__).with_name("protected-pg-backup.py"))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
PAYLOAD = b"PGDMP synthetic fixture\n"


class ProtectedBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pv-backup-control-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.backups = self.root / "backups"
        self.exports = self.root / "exports"
        self.exports.mkdir(mode=0o700)
        self.operator = pwd.getpwuid(os.geteuid()).pw_name
        self.dump = [sys.executable, "-c", "import sys;sys.stdout.buffer.write(" + repr(PAYLOAD) + ")"]
        self.validate = [sys.executable, "-c", "import sys;assert sys.stdin.buffer.read()==" + repr(PAYLOAD) + ";print('TABLE DATA fixture')"]

    def run_backup(self, dump=None, validate=None):
        return helper.backup(str(self.backups), str(self.exports), "review.dump", self.operator,
                             dump or self.dump, validate or self.validate)

    def test_private_from_first_write_with_permissive_caller_and_matching_export(self):
        self.backups.mkdir(mode=0o755)
        untouched = self.backups / "historical.dump"
        untouched.write_bytes(b"historical")
        untouched.chmod(0o644)
        mode_before = os.umask(0)
        try:
            dump = [sys.executable, "-c", "import os,stat,sys;assert stat.S_IMODE(os.fstat(1).st_mode)==0o600;"
                    "assert stat.S_IMODE(os.stat(" + repr(str(self.backups)) + ").st_mode)==0o700;"
                    "sys.stdout.buffer.write(" + repr(PAYLOAD) + ")"]
            result = self.run_backup(dump=dump)
        finally:
            os.umask(mode_before)
        source, exported = Path(result["backup"]), Path(result["operatorCopy"])
        for p in (source, exported, self.backups / "latest-dump.txt"):
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(exported.parent.stat().st_mode), 0o700)
        self.assertEqual(exported.stat().st_uid, os.geteuid())
        self.assertEqual(exported.parent.stat().st_uid, os.geteuid())
        self.assertEqual(source.read_bytes(), PAYLOAD)
        self.assertEqual(exported.read_bytes(), PAYLOAD)
        self.assertEqual((self.backups / "latest-dump.txt").read_text(), "review.dump\n")
        self.assertEqual(untouched.read_bytes(), b"historical")
        self.assertEqual(stat.S_IMODE(untouched.stat().st_mode), 0o644)

    def test_failed_dump_is_private_and_never_advertised(self):
        with self.assertRaisesRegex(RuntimeError, "dump failed"):
            self.run_backup(dump=[sys.executable, "-c", "import sys;print('partial');sys.exit(7)"])
        self.assertFalse((self.backups / "review.dump").exists())
        self.assertFalse((self.backups / "latest-dump.txt").exists())
        partials = list(self.backups.glob(".partial-*"))
        self.assertEqual(len(partials), 1)
        self.assertEqual(stat.S_IMODE(partials[0].stat().st_mode), 0o600)
        self.assertEqual(list(self.exports.iterdir()), [])

    def test_failed_or_empty_toc_never_advertises_success(self):
        for validator in ([sys.executable, "-c", "raise SystemExit(3)"],
                          [sys.executable, "-c", "print('not a table inventory')"]):
            with self.assertRaises(RuntimeError):
                self.run_backup(validate=validator)
            self.assertFalse((self.backups / "review.dump").exists())
            self.assertFalse((self.backups / "latest-dump.txt").exists())

    def test_existing_destination_file_or_symlink_is_never_replaced(self):
        self.backups.mkdir(mode=0o700)
        target = self.root / "unrelated"
        target.write_bytes(b"unchanged")
        destination = self.backups / "review.dump"
        for symlink in (False, True):
            if symlink:
                destination.symlink_to(target)
            else:
                destination.write_bytes(b"old dump")
            with self.assertRaises(FileExistsError):
                self.run_backup()
            self.assertEqual(target.read_bytes(), b"unchanged")
            self.assertEqual(destination.read_bytes(), b"unchanged" if symlink else b"old dump")
            destination.unlink()

    def test_directory_symlink_and_symlink_ancestor_are_refused(self):
        real = self.root / "real"
        real.mkdir(mode=0o755)
        self.backups.symlink_to(real, target_is_directory=True)
        with self.assertRaises(OSError):
            self.run_backup()
        self.assertEqual(stat.S_IMODE(real.stat().st_mode), 0o755)
        self.assertEqual(list(real.iterdir()), [])
        with self.assertRaises(OSError):
            helper.open_directory(str(self.backups / "child"))

    def test_destination_created_during_dump_cannot_be_clobbered(self):
        dump = [sys.executable, "-c", "from pathlib import Path;import sys;Path(" +
                repr(str(self.backups / "review.dump")) + ").write_bytes(b'concurrent');"
                "sys.stdout.buffer.write(" + repr(PAYLOAD) + ")"]
        with self.assertRaises(FileExistsError):
            self.run_backup(dump=dump)
        self.assertEqual((self.backups / "review.dump").read_bytes(), b"concurrent")
        self.assertFalse((self.backups / "latest-dump.txt").exists())

    def test_group_writable_export_parent_without_sticky_bit_is_refused(self):
        self.exports.chmod(0o775)
        with self.assertRaises(PermissionError):
            self.run_backup()
        self.assertEqual(list(self.exports.iterdir()), [])
        self.assertFalse((self.backups / "latest-dump.txt").exists())

    def test_latest_pointer_symlink_never_changes_its_target(self):
        self.backups.mkdir(mode=0o700)
        target = self.root / "unrelated"
        target.write_bytes(b"unchanged")
        (self.backups / "latest-dump.txt").symlink_to(target)
        self.run_backup()
        self.assertEqual(target.read_bytes(), b"unchanged")
        self.assertFalse((self.backups / "latest-dump.txt").is_symlink())

    def test_untrusted_owner_is_refused_even_with_private_or_sticky_permissions(self):
        original = os.fstat
        inode = self.exports.stat().st_ino
        for permissions in (0o700, 0o755, 0o1777):
            def changed_owner(fd):
                info = original(fd)
                if info.st_ino != inode:
                    return info
                fields = list(info)
                fields[0] = stat.S_IFDIR | permissions
                fields[4] = 123456 if os.geteuid() != 123456 else 123457
                return os.stat_result(fields)
            with patch.object(helper.os, "fstat", side_effect=changed_owner):
                with self.assertRaisesRegex(PermissionError, "ancestry must belong"):
                    self.run_backup()
            self.assertFalse(self.backups.exists())
            self.assertEqual(list(self.exports.iterdir()), [])

    def test_unsafe_ancestor_is_refused_before_dump(self):
        self.root.chmod(0o777)
        try:
            with self.assertRaisesRegex(PermissionError, "ancestry requires"):
                self.run_backup()
            self.assertFalse(self.backups.exists())
        finally:
            self.root.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
