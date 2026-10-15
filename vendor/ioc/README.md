# Bundled IOC snapshots

The upstream snapshots in this directory are **verbatim third-party community data**, not individually validated malware determinations. `manifest.json` records the download time, SHA256, origin and item counts. PhishShield is MIT licensed, IPGuard is CC BY 4.0 (original line comments retained), and anti-AD is an aggregation project licensed under MIT with upstream source rights to be checked separately.

The repository automatically refreshes these pinned-source snapshots using `.github/workflows/update-ioc-snapshots.yml`. Offline installation loads snapshots into the private SQLite cache without contacting upstream. Failed refreshes preserve the last successful cache; stale data is clearly flagged. The anti-AD feed **only marks advertisement/tracking domains**, not malicious domains.

- [PhishShield](https://github.com/Lu-yanmo/phishshield) — MIT, Copyright © 2026 Lu-yanmo.
- [IPGuard](https://github.com/chxovo/IPguard) — CC BY 4.0, attribution chxovo; any transformed redistribution must credit original and disclose changes.
- [anti-AD](https://github.com/privacy-protection-tools/anti-AD) — MIT, Copyright © 2017–2019 gently; aggregated upstream lists may have other licenses.

Do not remove upstream attribution or assume that an IOC match is proof of malicious behavior. The security analyzer neither executes upstream text nor automatically blocks any domain/IP.
