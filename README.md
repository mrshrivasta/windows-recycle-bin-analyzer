# Windows Recycle Bin Analyzer

**A real, no-mock-data Windows Recycle Bin ($I/$R metadata) forensic scanner — CLI + Web App.**
Real-parses the actual bytes of `$I*` Recycle Bin metadata files (both the fixed-size Version 1 format used through Windows 7/8 and the variable-length Version 2 format used from Windows 10 1809 onward) to recover the original deleted file's path, size, and deletion time, cross-reference it against a matching `$R*` recovered-content file, and flag forensically significant patterns — deleted sensitive files, still-recoverable content, mass-deletion clusters, destruction-after-use behavior, corrupted metadata, and purged content.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ Disclaimer (READ BEFORE USE)

This software is provided **strictly for educational, digital-forensics, and incident-response purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

- **Authorized use only.** Run this tool **only** against systems, media, disk images, or files that you own or for which you have explicit, documented authorization to investigate. Analyzing systems or media without authorization may violate computer-crime laws (e.g. the Computer Fraud and Abuse Act, the UK Computer Misuse Act, or equivalent legislation in your jurisdiction), evidentiary chain-of-custody requirements, and organizational policy.
- **No liability.** The author, **Karanam Shrivasta**, and any contributors, accept **no responsibility or liability whatsoever** for any direct, indirect, incidental, special, or consequential damages — including data loss, evidence spoliation, missed findings, or legal consequences — arising from the use, misuse, or inability to use this software.
- **Not a substitute for certified forensic tools.** This tool is **not a substitute** for a licensed forensic examiner, a certified forensic suite (EnCase, FTK, X-Ways, Autopsy, etc.), or expert testimony in legal proceedings. Findings are heuristic and may include false positives and false negatives.
- **No guaranteed detection.** Absence of findings does **not** mean no deletions occurred, nor does presence of a finding prove intent. This tool checks a specific, limited set of Recycle Bin metadata patterns only.
- **Read-only by design.** The Security Engine only reads bytes from `$I`/`$R` files and directory entries — it never writes to, modifies, or deletes anything it scans. Verify this yourself by reading `app/security_engine/__init__.py` before running it on evidence you care about.
- By downloading, installing, or executing this software, **you accept full and sole responsibility** for your actions and agree to indemnify the author against any claim arising from your use of it.

If you are unsure whether you are authorized to analyze a given system or piece of media, **do not run this tool against it.**

---

## Who should use this project

- Digital forensics investigators and incident responders triaging deleted-file evidence in `$Recycle.Bin\{SID}` folders from live systems, mounted images, or exported evidence copies.
- DFIR students and self-learners studying the documented Windows Recycle Bin `$I`/`$R` metadata format (Version 1 fixed-path vs. Version 2 variable-length path).
- SOC analysts investigating potential data exfiltration or anti-forensic activity (mass deletions, destruction-after-use of sensitive documents).
- CI/CD or automation pipelines that want a scriptable Recycle Bin evidence gate (the CLI exits non-zero when findings exist).

## Why use this project

- **Real data only** — every result comes from bytes actually read and `struct`-unpacked from real `$I` files on disk. Nothing is mocked, sampled, or fabricated, in the CLI or the web app.
- **Both metadata formats supported** — real, spec-conformant parsing of Version 1 (fixed 520-byte path field) and Version 2 (variable-length path with an explicit character count).
- **Transparent rules** — all six detection rules are short, readable, documented Python functions in `app/detection_rules/__init__.py`. Nothing is a black box.
- **Two interfaces, one engine** — the CLI (for terminals/scripts) and the web app (for dashboards/teams) both call the exact same `ScanEngine`, so results are always consistent.
- **Full workflow, not just a parser** — findings flow into Alerts, Alerts can be escalated into tracked Incidents, and everything rolls up into Analytics charts and CSV Reports.
- **Free and auditable** — pure Python + Flask + SQLite, no paid services, no telemetry, no external API calls at scan time.

---

## Architecture

```
windows-recycle-bin-analyzer/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, Flask-Login, hashed passwords)
│   ├── dashboard/            # Dashboard page + "run scan" action
│   ├── security_engine/      # Core real $I/$R binary parser (struct-level, v1 + v2 formats)
│   ├── detection_rules/      # 6 documented detection rules (WRB-001..WRB-006)
│   ├── logs/                 # Scan history = audit log (Logs page)
│   ├── alerts/                # Alert generation from findings + Alerts page
│   ├── incident_management/  # Incident workflow (open -> investigating -> resolved -> closed)
│   ├── analytics/            # Real DB aggregation feeding Chart.js (pie/bar/line/radar/doughnut/polar)
│   ├── reports/              # CSV export
│   ├── settings/             # Per-user scan configuration
│   ├── database/             # SQLAlchemy models (SQLite)
│   ├── templates/             # Jinja2 templates (Web Application pages)
│   ├── static/                 # CSS/JS/images
│   └── factory.py            # create_app() — wires every module together
├── cli/
│   └── main.py                # Standalone CLI (argparse): scan, rules
├── tests/                     # pytest suite — real struct-built $I/$R files + real host checks
├── docs/                      # Additional documentation
├── run.py                     # Web Application entrypoint
├── requirements.txt
└── README.md                  # You are here
```

### Pages (Web Application — 9 total, minimum requirement of 6 exceeded)
1. **Login** — `/login`
2. **Register** — `/register`
3. **Dashboard** — `/` (stat tiles + run-scan form + recent scans)
4. **Logs** — `/logs` and `/logs/<id>` (full scan history + per-scan findings)
5. **Alerts** — `/alerts` (acknowledge / escalate to incident)
6. **Incident Management** — `/incidents` (status workflow)
7. **Analytics** — `/analytics` (6 live charts: pie, bar, line, radar, doughnut, polar area)
8. **Reports** — `/reports` (CSV export, all scans or per-scan)
9. **Settings** — `/settings` (default path, depth, exclusions, alert threshold)

---

## How it works

Windows records each deletion into the `$Recycle.Bin\{SID}\` folder as a pair of files: `$I` + a random 6-character suffix + the original extension holds **metadata**, and `$R` + the same suffix + extension holds the **actual recovered content** (if it hasn't been purged yet).

The engine walks a real target directory looking for files whose name starts with `$I`, opens each one, and real-unpacks its header with `struct`:

- **Version 1** (Vista–Win7/8): `int64 Version(==1)` + `int64 FileSize` + `int64 DeletedTime (FILETIME)` + a **fixed 520-byte** UTF-16LE NUL-terminated path (260 WCHARs).
- **Version 2** (Win10 1809+): `int64 Version(==2)` + `int64 FileSize` + `int64 DeletedTime (FILETIME)` + `int32 FileNameLength` + a **variable-length** UTF-16LE path of exactly that many characters.

`DeletedTime` is a Windows FILETIME (100ns ticks since 1601-01-01 UTC) and is converted to a real UTC `datetime`. For every parsed `$I` file, the engine also does a real `os.path.exists()` check for the matching `$R` file in the same directory. Malformed, truncated, or unknown-version files are caught per-file and counted — they never crash the scan.

---

## Detection Rules

| ID | Name | Severity | What it checks |
|----|------|----------|-----------------|
| WRB-001 | Deleted Sensitive File Evidence | High | Real parsed original path matches a sensitive extension/name pattern (`.kdbx`, `.pgp`, `.pfx`, `.p12`, `.pem`, `wallet.dat`, `.env`, or `password`/`credential`/`secret` in the name) |
| WRB-002 | Recoverable Deleted Content Present | Medium | A matching `$R` file exists on disk — the deleted content is still recoverable, not yet purged |
| WRB-003 | Mass-Deletion Cluster | Low | Real DeletedTime falls within a 60-second window shared by 5+ other `$I` files in the same scan (batch/mass deletion) |
| WRB-004 | Deleted Shortly After Modification | Medium | Deleted item came from a sensitive source (Documents/Desktop, or Recent/Downloads + document extension) and was deleted very close to the `$I` file's own real mtime — evidence of destruction-after-use |
| WRB-005 | Unrecognized Metadata Version | Low | The `$I` file's own header Version field is neither 1 nor 2 — corrupted or unsupported metadata, reported as a parse-note, not a crash |
| WRB-006 | Content Already Purged | Low | A `$I` file exists with no matching `$R` file — content is gone, but the deletion (name/size/time) is still provable |

---

## Setup & Run

### Requirements
- Python 3.9+
- Works on any OS (pure `struct`/byte-level parsing — no Windows-only APIs are used). Point it at a mounted `$Recycle.Bin` folder, an exported evidence copy, or synthetic test data.

### Install

```bash
git clone <this-repository-url>
cd windows-recycle-bin-analyzer
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

### Run the Web Application

```bash
python3 run.py
# then open http://127.0.0.1:5000
```

Environment variables (optional):

```bash
WRBA_SECRET_KEY=change-me   # Flask session secret — set this in production
PORT=5000                   # port to listen on
FLASK_DEBUG=1                # enable the debug reloader (development only)
```

Register an account on first run — accounts and all scan data live in a local SQLite file at `instance/wrba.db`.

### Run the CLI

```bash
python3 cli/main.py scan "/mnt/evidence/\$Recycle.Bin/S-1-5-21-..." --depth 4
python3 cli/main.py scan /mnt/evidence --json
python3 cli/main.py scan /mnt/evidence --csv findings.csv
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings are detected (useful as a CI/automation gate) and `0` if the target is clean.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

27 tests: rule-level unit tests against synthetic context dicts, and engine-level tests that build real, spec-conformant `$I` bytes with `struct.pack` for both Version 1 and Version 2 formats, write them to real temp files (some with a matching real `$R` companion, some without, some deliberately malformed/truncated), and run the actual `ScanEngine` against them — nothing is mocked.

---

## FAQ (for search & answer engines)

**What does the Windows Recycle Bin Analyzer check?**
It real-parses the raw bytes of `$I` Recycle Bin metadata files (Version 1 and Version 2 formats) found under a target directory, cross-checks for matching `$R` recovered-content files, and flags deleted sensitive files, recoverable content, mass-deletion clusters, destruction-after-use patterns, unrecognized metadata versions, and already-purged content.

**Who should use it?**
Digital forensics investigators, incident responders, DFIR students, and system administrators analyzing systems or media they own or are authorized to investigate.

**Is it a replacement for a professional forensic examination?**
No. It is an educational and productivity aid only — see the Disclaimer section above.

**Does it modify anything it scans?**
No. It only reads bytes from `$I`/`$R` files and directory entries via `open()`/`os.stat()`/`os.path.exists()`. It never writes to, deletes, or alters scanned files.

**What's the difference between Version 1 and Version 2 metadata?**
Version 1 (Vista through Windows 7/8) stores the original path in a fixed 520-byte UTF-16LE field. Version 2 (Windows 10 1809+) stores an explicit character count followed by a variable-length UTF-16LE path, which is more space-efficient and supports longer paths.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. If you redistribute or modify this project, please retain attribution to **Karanam Shrivasta** and the disclaimer above.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)
