# Security

## Reporting

Do not put private data, credentials, real backups, or exploitable production details in a public issue. If the repository's Security tab offers private vulnerability reporting, use it. Otherwise ask the maintainer to establish a private reporting channel before sharing sensitive details. No private reporting channel or response-time commitment is currently guaranteed.

For a report, include the affected commit, Linux/Python versions, expected and observed behavior, and a minimal reproduction using synthetic files. Never include environment files, vault configuration from real systems, archive contents, or private health reports.

## Operational boundaries

- Archives are not encrypted. Restrict access to configuration and backup locations, and use trusted encrypted storage where needed.
- Keep an independent copy on a separate device or backup system. Local backups on the source disk do not protect against device failure.
- Quiesce applications or use a consistent snapshot. Use native database dumps for live databases; this tool does not coordinate application consistency.
- SHA-256 verification checks file content against the manifest, not the authenticity of the manifest. An attacker able to replace both can bypass that assurance.
- Run as a least-privileged account. Keep configuration, source, backup storage, and recovery destinations separate and under trusted control. Do not treat path checks as a sandbox against hostile concurrent filesystem changes.
- Restore only into a separate empty directory. Review recovered data before manual service activation. Original ownership, ACLs, and permissions are not reconstructed.
- Retention never deletes backups automatically. Incomplete backup or restore files may remain after failure; review them manually.
- Docker status is optional and read-only, but access to the Docker daemon itself is highly privileged.
- `.gitignore` does not remove already tracked files or guarantee secrecy. Never publish runtime files, archives, or private reports.

No external security audit or production certification is claimed. Test recovery with representative non-sensitive data before depending on this tool.
