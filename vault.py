#!/usr/bin/env python3
import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile


class VaultError(Exception):
    pass


def positive_int(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Enter a positive integer.") from None
    if number < 1:
        raise argparse.ArgumentTypeError("Enter a positive integer.")
    return number


def validate_paths(source, destination):
    if not source.is_dir() or source == Path("/"):
        raise VaultError("Select an existing dedicated source directory, not the filesystem root.")
    if source == destination or source in destination.parents or destination in source.parents:
        raise VaultError("Source and destination must not overlap.")


def digest_stream(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def private_write(path, content):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".write-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def load_config(path):
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
        source = Path(config["source"]).expanduser().resolve()
        destination = Path(config["destination"]).expanduser().resolve()
        retention = positive_int(str(config["retention"]))
        validate_paths(source, destination)
        if source == path.parent.resolve() or source in path.parent.resolve().parents:
            raise ValueError
        return {"source": str(source), "destination": str(destination), "retention": retention}
    except (OSError, KeyError, TypeError, ValueError, argparse.ArgumentTypeError, VaultError):
        raise VaultError("Invalid or incomplete vault configuration.") from None


@contextlib.contextmanager
def lock(directory):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(directory / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise VaultError("Another operation is using this vault.") from None
        yield


def scan_directory(source):
    files = []
    total = 0
    for path in sorted(source.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            size = os.fstat(stream.fileno()).st_size
            digest = digest_stream(stream)
        files.append({"path": path.relative_to(source).as_posix(), "size": size, "sha256": digest})
        total += size
    return files, total


def archive(source, destination, manifest):
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output, tarfile.open(fileobj=output, mode="w:gz", dereference=False) as bundle:
        for entry in manifest["files"]:
            file_fd = os.open(source / entry["path"], os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(file_fd, "rb") as stream:
                metadata = os.fstat(stream.fileno())
                member = tarfile.TarInfo(entry["path"])
                member.size = metadata.st_size
                member.mtime = metadata.st_mtime
                member.mode = 0o600
                bundle.addfile(member, stream)


def validate_archive(archive_path, manifest):
    try:
        expected = {}
        for entry in manifest["files"]:
            name = entry["path"]
            path = PurePosixPath(name)
            if not path.parts or "\x00" in name or path.is_absolute() or ".." in path.parts or name != path.as_posix() or name in expected:
                raise ValueError
            if not isinstance(entry["size"], int) or entry["size"] < 0:
                raise ValueError
            expected[name] = entry
        if manifest["file_count"] != len(expected) or manifest["total_bytes"] != sum(entry["size"] for entry in expected.values()):
            raise ValueError
        seen = set()
        with tarfile.open(archive_path, "r:gz") as bundle:
            for member in bundle:
                if not member.isfile() or member.name not in expected or member.name in seen:
                    raise ValueError
                entry = expected[member.name]
                if member.size != entry["size"]:
                    raise ValueError
                with bundle.extractfile(member) as stream:
                    if digest_stream(stream) != entry["sha256"]:
                        raise ValueError
                seen.add(member.name)
        if seen != set(expected):
            raise ValueError
    except (KeyError, TypeError, ValueError, OSError, tarfile.TarError, EOFError):
        raise VaultError("Archive integrity check failed: unsafe, damaged or mismatched backup.") from None


def health_report(directory, docker=False):
    disk = shutil.disk_usage(directory if directory.exists() else directory.parent)
    report = {
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "disk": {"total_bytes": disk.total, "used_bytes": disk.used, "free_bytes": disk.free},
        "load_average": list(os.getloadavg()),
    }
    if docker:
        try:
            result = subprocess.run(["docker", "ps", "--all", "--format", "{{json .}}"],
                                    text=True, capture_output=True, timeout=20, check=False)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            raise VaultError("Docker is unavailable or did not respond within 20 seconds.") from None
        if result.returncode:
            raise VaultError("Cannot query Docker. Check daemon access and permissions.")
        try:
            report["containers"] = [{key: item.get(key, "") for key in ("Names", "State", "Status")}
                                    for item in (json.loads(line) for line in result.stdout.splitlines() if line)]
        except (ValueError, AttributeError):
            raise VaultError("Docker returned an invalid status response.") from None
    return report


class Vault:
    def __init__(self, directory):
        self.directory = directory
        self.settings = directory / "vault.json"

    def config(self):
        if not self.settings.is_file():
            raise VaultError("No vault is configured here. Run init first.")
        return load_config(self.settings)

    def init(self, source, destination, retention):
        if self.settings.exists():
            raise VaultError("A vault is already configured here.")
        source, destination = source.expanduser().resolve(), destination.expanduser().resolve()
        validate_paths(source, destination)
        retention = positive_int(str(retention))
        if self.directory.resolve() == source or source in self.directory.resolve().parents:
            raise VaultError("Keep the vault configuration outside the source directory.")
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        if destination.is_symlink() or destination.stat().st_mode & 0o077:
            raise VaultError("Use a private destination directory (permissions 700).")
        private_write(self.settings, json.dumps({"source": str(source), "destination": str(destination), "retention": retention}, indent=2) + "\n")
        print("Vault configured. Archives are NOT encrypted. Stop writers or use a consistent snapshot before backup.")

    def backups(self):
        destination = Path(self.config()["destination"])
        return sorted(path for path in destination.iterdir()
                      if not path.is_symlink() and path.is_dir() and (path / "COMPLETE").is_file())

    def check(self):
        config = self.config()
        free = shutil.disk_usage(config["destination"]).free
        print(f"Source: {config['source']}\nDestination: {config['destination']}\nFree space: {free / 1024**3:.2f} GiB")
        print("No services are stopped automatically. Live databases require an application-native dump or snapshot.")
        if free < 1024**3:
            print("Warning: less than 1 GiB of destination space remains.")

    def backup(self):
        config = self.config()
        source, destination = Path(config["source"]), Path(config["destination"])
        if destination.stat().st_mode & 0o077:
            raise VaultError("Backup destination must be private (permissions 700).")
        files, total = scan_directory(source)
        if shutil.disk_usage(destination).free < total + 1024 * 1024:
            raise VaultError("Not enough free space for a conservative full backup estimate.")
        timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup_dir = destination / (timestamp + "-" + secrets.token_hex(3))
        backup_dir.mkdir(mode=0o700)
        manifest = {"created_at": timestamp, "file_count": len(files), "total_bytes": total, "files": files}
        private_write(backup_dir / "manifest.json", json.dumps(manifest, indent=2) + "\n")
        archive(source, backup_dir / "data.tar.gz", manifest)
        validate_archive(backup_dir / "data.tar.gz", manifest)
        private_write(backup_dir / "COMPLETE", "All archived file sizes and SHA-256 hashes verified.\n")
        print(f"Backup complete: {backup_dir} ({len(files)} files, {total} bytes).")
        print("Incomplete backups have no COMPLETE marker. No backup is deleted automatically.")
        self.retention_report()
        return backup_dir

    def retention_report(self):
        retention = self.config()["retention"]
        for old in self.backups()[:-retention]:
            print(f"Older than retention target; review manually: {old}")

    def verify(self):
        backups = self.backups()
        if not backups:
            raise VaultError("No complete backup is available.")
        latest = backups[-1]
        manifest = json.loads((latest / "manifest.json").read_text(encoding="utf-8"))
        validate_archive(latest / "data.tar.gz", manifest)
        print(f"Verified file content hashes: {latest}")
        return latest

    def restore(self, destination):
        backup = self.verify()
        destination = destination.expanduser().resolve()
        config = self.config()
        source, storage = Path(config["source"]), Path(config["destination"])
        for protected in (source, storage, self.directory.resolve()):
            if destination == protected or protected in destination.parents or destination in protected.parents:
                raise VaultError("Restore to a separate empty directory, not a source, vault or backup path.")
        if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
            raise VaultError("Restore destination must be an empty directory.")
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination.chmod(0o700)
        with tarfile.open(backup / "data.tar.gz", "r:gz") as bundle:
            for member in bundle:
                target = destination / member.name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with bundle.extractfile(member) as source_stream, target.open("xb") as output:
                    target.chmod(0o600)
                    shutil.copyfileobj(source_stream, output)
        print(f"Restored regular files to {destination}. Permissions are private; service activation is manual.")

    def status(self):
        backups = self.backups()
        print(f"Complete backups: {len(backups)}")
        if backups:
            print(f"Latest: {backups[-1]}")
        self.check()
        self.retention_report()


def parser():
    cli = argparse.ArgumentParser(description="ModernSoft Server Vault: private local backups with SHA-256 verification, isolated recovery and server health reports. Archives are not encrypted.")
    cli.add_argument("--directory", type=Path, default=Path.cwd() / ".server-vault")
    commands = cli.add_subparsers(dest="command")
    commands.add_parser("menu", help="Open the menu (default)")
    init = commands.add_parser("init", help="Configure non-overlapping source and backup directories")
    init.add_argument("--source", type=Path, required=True)
    init.add_argument("--destination", type=Path, required=True)
    init.add_argument("--retention", type=positive_int, default=7)
    for name in ("check", "backup", "verify", "status"):
        commands.add_parser(name)
    restore = commands.add_parser("restore", help="Recover latest backup into a separate empty directory")
    restore.add_argument("--destination", type=Path, required=True)
    restore.add_argument("--confirm", action="store_true")
    health = commands.add_parser("health", help="Disk/load report; optional read-only Docker status")
    health.add_argument("--docker", action="store_true")
    health.add_argument("--output", type=Path, help="Save a private local JSON report; no network delivery")
    return cli


def menu(directory):
    try:
        while True:
            print("\n" + "=" * 48 + "\n                   ModernSoft\n                 Server Vault\n" + "=" * 48)
            print("1. Configure vault\n2. Check source and destination\n3. Create verified backup\n4. Verify latest backup\n5. Show backup status\n6. Server health report\n7. Server and Docker status\n8. Restore latest backup to an empty directory\n0. Exit")
            print("Archives are NOT encrypted. Quiesce applications before backing up their data.")
            choice = input("Select an option: ").strip()
            if choice == "0":
                return 0
            options = []
            action = {"2": "check", "3": "backup", "4": "verify", "5": "status", "6": "health", "7": "health"}.get(choice)
            if choice == "1":
                source = input("Source directory: ").strip()
                destination = input("Private backup destination: ").strip()
                retention = input("Retention warning threshold [7]: ").strip() or "7"
                if not source or not destination:
                    print("Both directories are required.")
                    continue
                try:
                    positive_int(retention)
                except argparse.ArgumentTypeError as exc:
                    print(str(exc))
                    continue
                action, options = "init", ["--source", source, "--destination", destination, "--retention", retention]
            elif choice == "8":
                destination = input("Separate empty recovery directory: ").strip()
                if not destination:
                    print("A recovery directory is required.")
                    continue
                action, options = "restore", ["--destination", destination, "--confirm"]
            elif choice == "7":
                options = ["--docker"]
            if action is None:
                print("Invalid option.")
                continue
            if input(f"Run {action}? [yes/no, default: no]: ").strip().lower() not in {"yes", "y"}:
                print("Cancelled. No changes made.")
                continue
            main(["--directory", str(directory), action, *options])
    except (EOFError, KeyboardInterrupt):
        print("\nExiting Server Vault.")
        return 0


def main(argv=None):
    args = parser().parse_args(argv)
    directory = args.directory.expanduser().resolve()
    os.umask(0o077)
    if args.command in {None, "menu"}:
        return menu(directory)
    try:
        if directory == Path("/"):
            raise VaultError("Use a dedicated vault configuration directory.")
        if args.command == "health":
            report = json.dumps(health_report(directory, args.docker), indent=2) + "\n"
            if args.output:
                target = args.output.expanduser().resolve()
                fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "w") as stream:
                    stream.write(report)
                print(f"Private report saved: {target}")
            else:
                print(report)
            return 0
        with lock(directory):
            vault = Vault(directory)
            if args.command == "init":
                vault.init(args.source, args.destination, args.retention)
            elif args.command == "restore":
                if not args.confirm:
                    raise VaultError("Restore requires --confirm; only an empty destination is permitted.")
                vault.restore(args.destination)
            else:
                getattr(vault, args.command)()
        return 0
    except (VaultError, OSError, ValueError, tarfile.TarError, argparse.ArgumentTypeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted. Partial backups have no COMPLETE marker; no existing backups were deleted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
