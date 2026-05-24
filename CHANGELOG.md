# Changelog

All notable changes to this project are documented here.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/),
and dates are ISO 8601. Versions are git tags (currently unreleased — there is
no versioned release yet; entries below correspond to commits on `main`).

---

## [Unreleased]

### Changed — Robustness (post-polish gaps)
- **Streaming post-exploit output to disk** (`_run_nxc_action`): stdout now
  goes straight to the loot file via `subprocess.run(stdout=fh)` instead of
  `capture_output=True` (which buffered the full output in RAM). This kills
  the OOM-when-dumping-NTDS-on-a-real-DC class of failures — multi-hundred-MB
  dumps now stream cleanly regardless of available memory. Only the first
  64 KB are read back for the classifier (markers are always near the top).
  Added `PermissionError` / `OSError` (disk full) handling on the loot write.
- **`--cache-path <file>`**: custom SQLite cache location, so parallel /
  CI runs of the tool don't fight over the same `~/.cache/.../state.db`.
- **HashCracker retries on signal-kill**: when hashcat returns a negative
  exit code (SIGSEGV, OOM-killer), we automatically retry once with
  `-w 1` (lowest workload profile). The potfile is write-as-you-go so any
  plaintexts cracked before the crash are preserved across the retry.
- **`diagnose_zero_cracks` learns new patterns**: distinguishes OOM-kill
  (signal 9), segfault (signal 11), and generic signal kills, and emits
  actionable hints instead of the previous "try a bigger wordlist".
- 5 new pytest cases (segfault hint, OOM hint, --cache-path isolation,
  streaming-not-buffering subprocess kwargs, permission error on loot dir)
  — 70 total now.

### Changed — Error handling polish pass
- **Action-result classifier**: `_run_nxc_action` now returns a structured
  `NxcActionResult` instead of bool, and `_classify_action` decides between
  ✔ (`ok`: produced real data), ⊘ (`noop`: ran cleanly but nothing actionable,
  e.g. `STATUS_ACCESS_DENIED` or no SAM dump), and ✘ (`fail`: subprocess
  error). The previous "✔ sam" lie when nxc had exit-0-but-no-data is gone.
- **Per-action `ok_markers`** in `SMB_ENUM_ACTIONS` / `LDAP_ENUM_ACTIONS` /
  `SMB_SECRETS_ACTIONS` declare what success *looks like* in the output, so
  each action's verdict is grounded in actual content.
- **Status icons standardized** into module-level constants
  (`ICON_OK / ICON_NOOP / ICON_FAIL / ICON_WARN / ICON_TIMEOUT / ICON_SKIP /
   ICON_PWN3D / ICON_HARVEST / ICON_CRACK / ICON_BLOODHOUND / ICON_FINDING`)
  with a single, stable meaning each. Replaces ad-hoc colour+symbol mixes.
- **`_validate_flag_combinations`** warns at boot when flags can't possibly
  produce results given the rest of the config (e.g. `--crack` without
  `--secretsdump`/`--enum`; `--modules` with `--only ldap`).
- **`HashCracker` captures `stderr`** and exposes `diagnose_zero_cracks()`
  which converts hashcat error patterns into human-readable hints
  ("no hashes loaded", "mode unsupported", "wordlist exhausted", "no GPU
  detected") — replaces the misleading "try a bigger wordlist" suggestion
  when the real problem was a format mismatch.
- **`--ntds` skipped on non-DC** hosts via cache-driven `_is_likely_dc`
  (LDAP open ⇒ likely DC). Shows ⊘ "not a DC" instead of a confusing
  ⏱ "timed out".
- **`--strict` flag**: exits with code 1 if any real error occurred during
  the run. Errors are accumulated in `self.strict_errors` and printed in
  a final `_print_run_diagnostics()` block (capped at 20 to avoid wall-
  of-text). Useful for CI / scripted pipelines.
- **Typed subprocess errors** in `_collect_target_results`: explicit
  handling for `FileNotFoundError` (binary disappeared mid-run),
  `PermissionError` (loot dir not writable), `MemoryError` (e.g. huge NTDS
  output) instead of a generic `Exception` catch-all.
- **SQLite `timeout=30`s** on the cache connection — no more "database is
  locked" crashes when two runs of the tool race on the same `state.db`.
- **BloodHound "no domain cred available" → ⊘ yellow**, not ✘ red (it's
  expected when only local-auth creds are valid).
- **Warnings/errors → stderr**, live findings and per-host summary remain
  on stdout. Piping output through `tee` / `grep` now behaves predictably.
- 14 new pytest cases (classifier matrix, flag-combo validation, cracker
  diagnostics, DC heuristic, strict error collection) — 65 total now.

### Added — Hash cracking
- **`--crack`** — auto-cracks every hash the post-exploit phase pulls out
  (NT from SAM/LSA/NTDS via `--secretsdump`, AS-REP from `--asreproast`,
  TGS-REP from `--kerberoasting`) with `hashcat -m {1000,18200,13100}` or
  `john --format={nt,krb5asrep,krb5tgs}` as a fallback.
- **Rockyou auto-discovery** under `/usr/share/wordlists/`,
  `/usr/share/seclists/...`, `~/wordlists/`, with auto-decompression of
  `.gz` form on first use. `--wordlist <path>` to override.
- **Cracked plaintexts auto-appended** to the grow-combo file in
  `user:password` form → next run sprays the harvested creds without
  manual editing. This closes the loop: pwn host → dump SAM → crack with
  rockyou → spray plaintexts across the rest of the network.
- New CLI: `--crack`, `--wordlist`, `--cracker {hashcat,john,auto}`,
  `--crack-rules`, `--crack-timeout`. Pre-flight check: missing
  cracker/wordlist disables the feature gracefully (like `--bloodhound`).
- `HashCracker` class extracted as standalone for testability (14 new
  pytest cases: discovery, gz handling, potfile parsing, cmd builder for
  hashcat/john, kerberos username regex).

### Added — Tier D (cleanup)
- `CHANGELOG.md` (this file).
- `.github/workflows/ci.yml` — runs `pytest` and `bash -n scripts/*.sh` on
  every push / PR across Python 3.10, 3.11, 3.12.
- `scripts/record-demo.sh` — asciinema-based recipe for refreshing the
  demo GIF reproducibly.

### Added — Tier C (quality / power-user)
- **pytest suite** under `tests/` (37 cases): parsers, command builder,
  credential matcher, protocol filters, TOML loader, DNS SRV parsing.
- **`--config <file.toml>`** — load defaults from TOML; CLI flags still win.
  Stdlib `tomllib` on 3.11+, fallback to tiny line parser for 3.10.
- **`--update-nxc`** — shortcut that execs `scripts/update-nxc.sh` and exits.
- **DNS SRV DC discovery** — queries `_ldap._tcp.dc._msdcs.<domain>` via
  `dig`/`nslookup` before falling back to nmap + banner heuristics. Results
  persisted to cache with `source='dns_srv'`.

### Added — Tier B (auto-pwn AD)
- **`--enum` now covers LDAP** — `--users`, `--admin-count`, `--groups`,
  `--asreproast`, `--kerberoasting` into `loot/<host>/ldap/domain/`.
- **`--secretsdump`** — on (Pwn3d!) SMB cred, auto-fires `--sam`/`--lsa`/
  `--ntds`; harvested NT hashes auto-appended in combo-file format to
  `--grow-combo` (default `loot/auto-grown-creds.txt`) — pass that file as
  `--combo` next run to spray the new creds.
- **`--export-json`/`--export-csv`** — structured run summary with valid
  creds, DC discoveries, harvested hashes, lockout warnings.
- **Lockout policy detection** — parses `--pass-pol` output, warns loudly
  when threshold > 0 and the spray would exceed it, suggests `--delay`.
- **`_pick_best_cred`** picks the strongest cred (pwn3d > local-auth >
  hash) for each post-exploit step.

### Added — Tier A (fix-the-blockers)
- **`--stop-on-success`** — bail out of a `(protocol, host)` loop after the
  first valid cred (avoids account lockout, saves time).
- **(Pwn3d!) highlight** — red 💀 prefix on live findings + dedicated
  "ADMIN PWN3D" block in the per-host summary.
- **Pre-flight `nxc` check** — fail fast with code 127 and a friendly hint
  if `nxc` isn't in `PATH`.
- **`--only` / `--exclude`** — protocol filters with validation.

### Added — `update-nxc.sh` & graphics fixes
- **`scripts/update-nxc.sh`** — install/update the official `nxc` binary
  from GitHub Releases. Detects platform, walks recent releases until it
  finds one with a matching asset, idempotent, default install to
  `~/.local/bin/nxc`. Strips macOS Gatekeeper quarantine.
- Fixed banner wrap (path truncation + dynamic `shutil.get_terminal_size`)
  and `_match_msg_to_credential` for multi-cred runs.

### Added — low-power, grouped CLI, air-gapped, README
- **`--low-power`** preset (workers=3, max-retry=1, longer timeouts,
  delay=0.5s) for weak VMs.
- **`--delay` / `--jitter`** for lockout-safe spraying.
- Tunable timeouts: `--netexec-timeout`, `--subprocess-timeout`, `--max-retry`.
- Argparse args grouped into 6 sections + numbered examples epilog.
- `scripts/bundle-airgapped.sh` — produces a self-contained tarball
  (tool + wheels + optional pre-built nxc binary + install-offline.sh)
  for offline / air-gapped deployment.
- `Dockerfile` + `.dockerignore` for docker save / docker load workflow.
- README restructured: TOC, Quick Start, Why, Install (standard / offline /
  Docker), grouped Usage, compact CLI reference and constants tables.

### Added — commands transcript
- **`commands-*.log`** — every command (nmap, nxc auth, nxc post-exploit,
  bloodhound-python) appended in shell-quoted form (`shlex`), with comment
  headers (`# <iso> [label] target=<host>`). Pasteable into OSCP reports
  unchanged. `--cmd-log <path>` to override, `--no-cmd-log` to disable.

### Added — nmap pre-scan, hash/combo auth, BloodHound auto-collect, verbosity
- **`--nmap`** pre-scan filters protocols by actually-open ports (massive
  speedup on dead hosts and wide CIDRs); CIDR expansion handled by nmap.
- **SQLite cache** at `~/.cache/netexec-automator/state.db` with
  `--cache-ttl` (default 24h) and `--no-cache` bypass; dead hosts cached
  via sentinel row.
- **`--scan-only`** for recon without firing any nxc auth attempts.
- **`-H/--hash`** — NT or LM:NT pass-the-hash (single or file).
- **`--combo`** — per-line auto-detect (password / NT / LM:NT), with `#`
  comments and blank-line tolerance.
- **`-d/--domain`** (suppressed on `--local-auth`), **`-k/--kerberos`**
  (only emitted for protocols that support it).
- **`--null-session`** prepends null / `Guest:''` / `anonymous:''` as
  quick-wins.
- Hash creds auto-skipped on SSH/FTP/VNC/NFS with coherent progress.
- **`-v/-vv` and `-q`** — from silent (creds only) to full debug.
- **DC detection** from nxc SMB banner + LDAP/SMB nmap-port signal.
- **`--enum`** runs shares/users/sessions/loggedon/pass-pol against best
  valid SMB cred, output to `loot/<host>/smb/<scope>/`.
- **`--modules X,Y`** runs nxc `-M` modules with dedicated loot files.
- **`--bloodhound`** auto-invokes `bloodhound-python -c All --zip` per
  discovered domain; results deduped in `bloodhound_runs` table with
  `--bloodhound-ttl` (default 24h) and `--bloodhound-force` override.
- Refactors: `Credential` dataclass, `HostCache`, `NmapScanner`,
  `LootStore`, `BloodHoundRunner` extracted as standalone classes for
  testability.
