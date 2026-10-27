# Contributing

Keep changes focused and discuss substantial behavior changes in an issue before implementation.

## Local checks

Use Linux and Python 3.10 or newer. No third-party Python packages are required.

```bash
python3 -m unittest discover -s . -p 'test_vault.py'
bash -n vault.sh
```

Use temporary directories and synthetic data in tests. Mock Docker responses rather than requiring a daemon. Never use production data, privileged host paths, real credentials, or private backup archives as fixtures.

## Project expectations

- Keep the CLI in English and maintain both English and explicitly right-to-left Persian documentation.
- Preserve default-no menu confirmations, private permissions, archive verification, no-overwrite recovery, and non-destructive retention warnings.
- Do not silently stop services, delete backups, upload data, or schedule jobs.
- Add regression tests for behavior changes. Document limitations instead of promising unsupported recovery guarantees.
- Include only intended source, tests, and documentation in commits. Do not publish runtime configuration, reports, archives, or secrets.

Contributions are distributed under the project's MIT license. Preserve the existing copyright and permission notice.
