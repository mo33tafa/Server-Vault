import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import vault


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "example.txt").write_text("ModernSoft test data\n")
        self.destination = self.root / "backups"
        self.manager = vault.Vault(self.root / "config")

    def initialize(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.manager.init(self.source, self.destination, 7)

    def test_initialization(self):
        self.initialize()
        self.assertEqual(self.manager.config()["source"], str(self.source))
        self.assertEqual(self.manager.config()["retention"], 7)

    def test_duplicate_initialization_rejected(self):
        self.initialize()
        with self.assertRaises(vault.VaultError):
            self.manager.init(self.source, self.destination, 7)

    def test_destination_inside_source_rejected(self):
        with self.assertRaises(vault.VaultError):
            self.manager.init(self.source, self.source / "backups", 7)

    def test_missing_config(self):
        with self.assertRaises(vault.VaultError):
            self.manager.config()

    def test_positive_retention(self):
        self.assertEqual(vault.positive_int("3"), 3)
        for value in ("0", "-1", "invalid"):
            with self.assertRaises(Exception):
                vault.positive_int(value)

    def test_manifest_and_archive(self):
        self.initialize()
        with contextlib.redirect_stdout(io.StringIO()):
            self.manager.backup()
            self.manager.verify()
        backup = next(self.destination.iterdir())
        self.assertTrue((backup / "COMPLETE").exists())
        manifest = json.loads((backup / "manifest.json").read_text())
        self.assertEqual(manifest["file_count"], 1)
        self.assertEqual(manifest["files"][0]["path"], "example.txt")
        self.assertEqual(len(manifest["files"][0]["sha256"]), 64)

    def test_symlinks_not_archived(self):
        outside = self.root / "outside.txt"
        outside.write_text("not included")
        (self.source / "link").symlink_to(outside)
        files, _ = vault.scan_directory(self.source)
        self.assertEqual([item["path"] for item in files], ["example.txt"])

    def test_archive_manifest_mismatch(self):
        self.initialize()
        with contextlib.redirect_stdout(io.StringIO()):
            self.manager.backup()
        backup = next(self.destination.iterdir())
        with self.assertRaises(vault.VaultError):
            vault.validate_archive(backup / "data.tar.gz", {"files": []})

    def create_backup(self):
        self.initialize()
        with contextlib.redirect_stdout(io.StringIO()):
            return self.manager.backup()

    def test_same_size_content_tampering_detected(self):
        backup = self.create_backup()
        (self.source / "example.txt").write_text("X" * len("ModernSoft test data\n"))
        manifest = json.loads((backup / "manifest.json").read_text())
        altered = self.root / "altered.tar.gz"
        vault.archive(self.source, altered, manifest)
        with self.assertRaises(vault.VaultError):
            vault.validate_archive(altered, manifest)

    def test_restore_to_empty_directory(self):
        self.create_backup()
        recovery = self.root / "recovery"
        with contextlib.redirect_stdout(io.StringIO()):
            self.manager.restore(recovery)
        self.assertEqual((recovery / "example.txt").read_text(), "ModernSoft test data\n")
        self.assertEqual(stat.S_IMODE((recovery / "example.txt").stat().st_mode), 0o600)

    def test_restore_never_overwrites_existing_files(self):
        self.create_backup()
        recovery = self.root / "recovery"
        recovery.mkdir()
        (recovery / "keep").write_text("unchanged")
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(vault.VaultError):
            self.manager.restore(recovery)
        self.assertEqual((recovery / "keep").read_text(), "unchanged")

    def test_restore_protected_paths_rejected(self):
        self.create_backup()
        for path in (self.source, self.destination, self.root, self.manager.directory):
            with self.subTest(path=path), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(vault.VaultError):
                self.manager.restore(path)

    def test_tampered_config_cannot_make_recursive_backup(self):
        self.initialize()
        config = json.loads(self.manager.settings.read_text())
        config["destination"] = str(self.source / "recursive")
        self.manager.settings.write_text(json.dumps(config))
        with self.assertRaises(vault.VaultError):
            self.manager.config()

    def test_configuration_cannot_be_included_in_source(self):
        manager = vault.Vault(self.source / "config")
        with self.assertRaises(vault.VaultError):
            manager.init(self.source, self.destination, 7)

    def test_permissions_are_private(self):
        backup = self.create_backup()
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode) & 0o777, 0o700)
        for name in ("data.tar.gz", "manifest.json", "COMPLETE"):
            self.assertEqual(stat.S_IMODE((backup / name).stat().st_mode), 0o600)

    def test_retention_only_warns_and_keeps_backups(self):
        self.initialize()
        config = self.manager.config()
        config["retention"] = 1
        self.manager.settings.write_text(json.dumps(config))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.manager.backup()
            self.manager.backup()
        self.assertEqual(len(self.manager.backups()), 2)
        self.assertIn("review manually", output.getvalue())

    def test_source_change_prevents_complete_marker(self):
        self.initialize()
        original = vault.scan_directory
        def changing_source(source):
            result = original(source)
            (source / "example.txt").write_text("changed")
            return result
        with patch.object(vault, "scan_directory", side_effect=changing_source), self.assertRaises(vault.VaultError):
            self.manager.backup()
        self.assertFalse(list(self.destination.glob("*/COMPLETE")))

    def test_hardlinks_become_independent_regular_archive_files(self):
        os.link(self.source / "example.txt", self.source / "hardlink.txt")
        backup = self.create_backup()
        with tarfile.open(backup / "data.tar.gz") as bundle:
            self.assertTrue(all(member.isfile() for member in bundle))

    def test_unsafe_archive_paths_rejected(self):
        for name in ("../escape", "/absolute", "./noncanonical"):
            manifest = {"files": [{"path": name, "size": 0, "sha256": "0" * 64}], "file_count": 1, "total_bytes": 0}
            with self.subTest(name=name), self.assertRaises(vault.VaultError):
                vault.validate_archive(self.root / "missing.tar.gz", manifest)

    def test_concurrent_operations_rejected(self):
        with vault.lock(self.manager.directory):
            with self.assertRaises(vault.VaultError):
                with vault.lock(self.manager.directory):
                    self.fail("Second lock acquired")

    def test_docker_health_only_reports_selected_status_fields(self):
        response = subprocess.CompletedProcess([], 0, stdout='{"Names":"demo","State":"running","Status":"Up","Other":"excluded"}\n')
        with patch.object(vault.subprocess, "run", return_value=response) as command:
            report = vault.health_report(self.root, docker=True)
        self.assertEqual(report["containers"], [{"Names": "demo", "State": "running", "Status": "Up"}])
        self.assertEqual(command.call_args.args[0][:3], ["docker", "ps", "--all"])
        self.assertNotIn("shell", command.call_args.kwargs)

    def test_docker_unavailable_is_clear_error(self):
        with patch.object(vault.subprocess, "run", side_effect=FileNotFoundError), self.assertRaises(vault.VaultError):
            vault.health_report(self.root, docker=True)

    def test_health_report_does_not_overwrite_existing_file(self):
        target = self.root / "report.json"
        target.write_text("keep")
        with contextlib.redirect_stderr(io.StringIO()):
            result = vault.main(["--directory", str(self.root), "health", "--output", str(target)])
        self.assertEqual(result, 1)
        self.assertEqual(target.read_text(), "keep")

    def test_menu_default_confirmation_cancels(self):
        with patch("builtins.input", side_effect=["3", "", "0"]), patch.object(vault, "main") as main, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(vault.menu(self.root), 0)
        main.assert_not_called()

    def test_menu_eof_during_setup_exits_cleanly(self):
        with patch("builtins.input", side_effect=["1", EOFError]), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(vault.menu(self.root), 0)

    def test_menu_exit_has_brand(self):
        from unittest.mock import patch
        output = io.StringIO()
        with patch("builtins.input", return_value="0"), contextlib.redirect_stdout(output):
            self.assertEqual(vault.menu(self.root), 0)
        self.assertIn("ModernSoft", output.getvalue())
        self.assertIn("Server Vault", output.getvalue())


if __name__ == "__main__":
    unittest.main()
