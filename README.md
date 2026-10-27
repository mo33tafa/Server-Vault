<p dir="ltr" align="left">
<a href="README.md" aria-label="English documentation"><img src="assets/language-en.svg" width="168" height="48" alt="English — United Kingdom flag"></a>
<a href="README.fa.md" aria-label="راهنمای فارسی"><img src="assets/language-fa.svg" width="168" height="48" alt="فارسی — پرچم ایران"></a>
</p>

# ModernSoft Server Vault

A menu-driven Linux tool for local file backups, SHA-256 integrity verification, isolated recovery, and server/Docker health reports. Built with the Python standard library; no Python packages to install.

**Archives are not encrypted.** Private filesystem permissions are not encryption. Keep another copy on a separate device or trusted backup system; a backup on the same disk cannot protect against disk failure.

## Requirements

- Linux with Python 3.10 or newer.
- Bash for the optional launcher.
- Read access to the selected source and write access to the configuration and backup locations.
- Docker CLI and daemon access only for the optional Docker status report. Docker access is highly privileged; do not grant it just to use file backups.

No automatic installation, network delivery, service changes, or scheduled jobs are performed. Root access is not required when your directories are accessible.

## Quick start

Clone the repository, then enter its directory:

```bash
git clone https://github.com/mo33tafa/Server-Vault.git
cd Server-Vault
bash vault.sh
```

The English-language interactive menu opens by default. Persian documentation does not change the CLI language. Operations require confirmation; the default answer is no.

| Option | Action |
| --- | --- |
| 1 | Configure source, private backup destination, and retention warning threshold |
| 2 | Check source, destination, and available space |
| 3 | Create a full backup and verify its file contents |
| 4 | Verify the latest complete backup |
| 5 | Show complete backups and retention warnings |
| 6 | Report disk usage and system load averages |
| 7 | Include read-only Docker container status |
| 8 | Restore the latest complete backup into a separate empty directory |
| 0 | Exit |

## Command-line workflow

The following paths are examples. Select an existing dedicated source directory, and keep the source, configuration, backup store, and recovery directory separate. Use the same `--directory` for every operation.

```bash
python3 vault.py --directory ./vault-config init \
  --source ./application-files \
  --destination ./backups \
  --retention 7

python3 vault.py --directory ./vault-config check
python3 vault.py --directory ./vault-config backup
python3 vault.py --directory ./vault-config verify
python3 vault.py --directory ./vault-config status

python3 vault.py --directory ./vault-config restore \
  --destination ./recovery --confirm
```

`application-files` must already exist. If the backup destination already exists, its permissions must be private (`700`). If it does not exist, initialization creates it privately. Run from a consistent working directory or use absolute paths. By default, configuration is stored in `.server-vault` under the current working directory, not beside the script.

### Health reports

```bash
python3 vault.py health
python3 vault.py health --docker
python3 vault.py health --output ./health-report.json
python3 vault.py --help
```

Health reports include disk usage and load averages, not a full monitoring or alerting service. Docker mode reads container names, states, and status text. Reports remain local. `--output` requires an existing parent directory and refuses to overwrite an existing file.

## What a backup contains

Each backup gets a unique timestamped directory containing:

- `data.tar.gz`: a full compressed archive of regular files.
- `manifest.json`: relative paths, sizes, and SHA-256 hashes.
- `COMPLETE`: created only after archive content verification succeeds.

Incomplete backups remain without a `COMPLETE` marker. They are not selected for recovery. Retention is a warning threshold, not automatic deletion: with `--retention 7`, older complete backups are reported for manual review, not removed. This number is a backup count, not a number of days.

## Safety and limitations

- Stop writers or take a consistent snapshot before backing up. Changing files can cause backup failure; file hashing does not create an application-consistent snapshot.
- Live databases need an application-native dump or appropriate snapshot first. This tool does not create database dumps or stop services.
- SHA-256 checks detect content mismatches, but manifests are not digitally signed. Someone who can replace both archive and manifest can replace the recorded hashes too.
- Symbolic links, empty directories, and special files are not preserved. Hard-linked files are archived as independent regular files.
- Original owners, permissions, ACLs, and extended attributes are not preserved. Restored directories use private permissions and files use `600`.
- Restore selects the latest complete backup and requires a separate empty destination. It does not overwrite a running application or activate services. A failed restore may leave partial files; review them and use a new empty directory for a retry.
- There is no encryption, incremental backup, cloud upload, automatic scheduling, automatic cleanup, whole-system image, or web dashboard.
- Keep configuration and backup storage under your control. Use least-privileged accounts; this tool is not a sandbox for untrusted directories or archives.
- Backups may contain private application data. `.gitignore` is not a security boundary: never commit runtime configuration, archives, or real reports.

## Development and testing

```bash
python3 -m unittest discover -s . -p 'test_vault.py'
bash -n vault.sh
```

Tests use temporary directories and simulated Docker responses; they do not require a running Docker daemon. A passing suite is not a production backup-and-recovery guarantee: rehearse recovery with representative data before relying on it.

See [Contributing](CONTRIBUTING.md) and [Security](SECURITY.md).

## License

[MIT](LICENSE), copyright (c) 2026 Mostafa Heshmatpour. Copies or substantial portions must retain the copyright and permission notice. Commercial use and modification are allowed; an on-screen credit badge is not required. The project is provided without warranty under the license terms.
