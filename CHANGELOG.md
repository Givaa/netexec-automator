# Changelog

All notable changes to this project are documented here.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/),
and dates are ISO 8601. Tags follow semver; entries grouped by tag below.

---

## [Unreleased]

### Changed — Output redesigned (default is now concise)
- The default verbosity used to dump every single nxc auth attempt
  per protocol per host — useful for debugging, noisy in practice. The
  output has been rethought around what the operator actually wants to
  see at a glance:
  - **`-q`** (unchanged): only valid credentials, one per line.
  - **default** (new): per-host **one-line recap grouped by outcome**
    (💀 admin / ⚡ valid / ⏱ timeouts / ✘ rejected), followed by a
    single **FINAL REPORT** at end-of-run that aggregates everything.
  - **`-v`** (new): everything in default, **plus** the original
    per-protocol verbose breakdown ("Detailed Results") with every
    `[+]`/`[-]`/`[!]` line. Plus the existing -v stuff (commands log,
    cache hit/miss, DC detection, failed-auth lines).
  - **`-vv`** (unchanged): + raw `[*]` info, raw nmap output.
- The end-of-run **FINAL REPORT** is the centrepiece. Sections shown
  only when non-empty:
    - 💀 `ADMIN PWN3D (N)` — host → protocol → cred (raw nxc [+] line)
    - ⚡ `VALID CREDENTIALS (N)` — non-pwn3d successes
    - 🧪 `HASHES HARVESTED` — counts of NT (SAM/LSA/NTDS) and Kerberos
      hashes plus pointer to the grow-combo file
    - 🔓 `CRACKED PLAINTEXT (N)` — user:password recovered by hashcat
    - 🩸 `BLOODHOUND (N domains)` — collected zips with paths
    - ⊘ `NO RESPONSE (N)` — dead / unreachable targets (capped at 10
      shown, plus a "+N more" tail)
    - `✘ no valid credentials found` if literally nothing landed.
- Hostnames from the PTR resolver are inlined in the report
  (`10.10.10.5 (dc01.corp.local)`) for readability.
- New per-instance tracking: `self.dead_hosts` (populated when a target
  has no open ports / is unreachable) and `self.bloodhound_results`
  (populated during `_run_bloodhound_pass`).
- 15 new pytest cases in `tests/test_output.py` covering the outcome
  classifier matrix, recap grouping, --no-banner / -v output paths, all
  FINAL REPORT sections, and quiet-mode suppression — 130 total.

### Added
- **Decorative startup banner** with NXA block-letter ASCII art (sliver-style),
  credits to Giovanni Rapa (@Givaa) + GitHub URL, and a random quote drawn
  from a curated pool (LOTR, Hackers, WarGames, Mr. Robot, Pokémon, The
  Matrix, Yoda, The Mandalorian — each picked because it captures the
  "why one when you can have them all?" multi-protocol essence).
  Implementation: `netexec_automator/banner.py`, pure Python, no deps.
- New flag `--no-banner` suppresses the decorative banner entirely; the
  run-summary table is still shown so scripted runs keep their context.
- Run-summary table refactored into a clean two-column layout with
  uniform padding (`_CFG_KEY_W` / `_CFG_VAL_W` / `_CFG_KEY2_W`). The
  previous staircase look ("Targets Count" 13 chars vs "Composition"
  11 chars, columns starting at different offsets) is gone — every row
  now lines up under the same separator characters. Single-column rows
  (Pacing / Filters / Cmd log / Cracking) flow underneath without
  breaking the table border.
- 8 new pytest cases for the banner (rendering, credits presence,
  uniform-width rows, quote-pool integrity, --no-banner propagation) —
  115 total now.

### Added (earlier this cycle)
- **Reverse-DNS PTR alongside target IPs** in the on-screen output. Each
  host header now prints `► 10.10.10.5 (dc01.corp.local)` when DNS
  resolves the IP, mirroring NetExec's classic `(name:…) (domain:…)`
  banner format. Implementation: stdlib `socket.gethostbyaddr` with an
  in-memory cache and a configurable per-host timeout — no new
  dependencies, fails silently on no-PTR / DNS-down so it never blocks
  the run. The same enrichment applies to the quiet-mode credential
  one-liners.
- New flags: `--no-resolve` to disable entirely, `--resolve-timeout`
  (default 2.0 seconds) to tune the lookup budget.
- 12 new pytest cases covering the resolver (PTR success, trailing-dot
  stripping, herror / gaierror fallback, positive- and negative-result
  caching, timeout save/restore, hostname pass-through, IP detection,
  `--no-resolve` wiring) plus 2 integration cases — 107 total.

---

## [0.1.0] — 2026-05-24

First tagged release. Marks the codebase as stable enough to depend on:
all features described in the README are implemented, tested (93 pytest
cases including snapshots against captured nxc/nmap output and an
integration suite driven by a nxc-mock subprocess), and exercised in
smoke runs. The single-file script has been refactored into the
`netexec_automator/` package; the `netexec-automator.py` CLI invocation
is unchanged and remains the supported entry point.

### Tests safety net + package split
- `tests/test_snapshots.py` (14 cases) verifies parsers/classifiers
  against real-shape fixtures in `tests/fixtures/nxc_outputs/` — locks
  in expectations against future nxc format changes.
- `tests/test_integration.py` (9 cases) launches the actual CLI as a
  subprocess with `tests/fixtures/nxc-mock.sh` shimmed into PATH.
  Exercises `run()`, `_post_exploit_host`, `_collect_target_results`,
  threading, progress bar, `--strict` exit path, `--export-json` shape,
  commands.log contents, `--only` filter, secretsdump → grow-combo loop.
- Refactor: monolithic `netexec-automator.py` (2813 lines) split into
  the `netexec_automator/` package (11 modules: constants, _utils,
  types, loot, cache, scanner, bloodhound, cracker, automator, cli,
  __init__). The CLI script is now an 18-line thin launcher. Public
  surface unchanged — `import netexec_automator as nxa` re-exports
  every top-level symbol the old single-file exposed.

### Robustness (post-polish gaps)
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

### Error handling polish pass
- **Action-result classifier**: `_run_nxc_action` returns a structured
  `NxcActionResult` instead of bool, and `_classify_action` decides between
  ✔ (`ok`: produced real data), ⊘ (`noop`: ran cleanly but nothing actionable,
  e.g. `STATUS_ACCESS_DENIED` or no SAM dump), and ✘ (`fail`: subprocess
  error). The previous "✔ sam" lie when nxc had exit-0-but-no-data is gone.
- **Per-action `ok_markers`** in `SMB_ENUM_ACTIONS` / `LDAP_ENUM_ACTIONS` /
  `SMB_SECRETS_ACTIONS` declare what success *looks like* in the output, so
  each action's verdict is grounded in actual content.
- **Status icons standardized** into module-level constants with one
  stable meaning each.
- **`_validate_flag_combinations`** warns at boot when flags can't possibly
  produce results given the rest of the config.
- **`HashCracker` captures `stderr`** and exposes `diagnose_zero_cracks()`.
- **`--ntds` skipped on non-DC** hosts via cache-driven `_is_likely_dc`.
- **`--strict` flag**: exits with code 1 if any real error occurred.
- **Typed subprocess errors** in `_collect_target_results`: explicit
  handling for `FileNotFoundError`, `PermissionError`, `MemoryError`.
- **SQLite `timeout=30`s** on the cache connection.
- **BloodHound "no domain cred available" → ⊘ yellow**, not ✘ red.
- **Warnings/errors → stderr**, live findings and per-host summary stay
  on stdout.

### Hash cracking
- **`--crack`** — auto-cracks every hash the post-exploit phase pulls out
  (NT from SAM/LSA/NTDS via `--secretsdump`, AS-REP from `--asreproast`,
  TGS-REP from `--kerberoasting`).
- **Rockyou auto-discovery** with auto-decompression of `.gz` form on
  first use. `--wordlist <path>` to override.
- **Cracked plaintexts auto-appended** to the grow-combo file in
  `user:password` form → next run sprays the harvested creds without
  manual editing.

### Tier D (cleanup)
- `CHANGELOG.md`.
- `.github/workflows/ci.yml` — runs `pytest` and `bash -n scripts/*.sh`
  on every push / PR across Python 3.10–3.13.
- `scripts/record-demo.sh` — asciinema-based recipe for refreshing the
  demo GIF reproducibly.

### Tier C (quality / power-user)
- **pytest suite** (37 cases at this layer): parsers, command builder,
  credential matcher, protocol filters, TOML loader, DNS SRV parsing.
- **`--config <file.toml>`** — load defaults from TOML; CLI flags still win.
- **`--update-nxc`** — shortcut that execs `scripts/update-nxc.sh` and exits.
- **DNS SRV DC discovery** — queries `_ldap._tcp.dc._msdcs.<domain>` via
  `dig`/`nslookup`.

### Tier B (auto-pwn AD)
- **`--enum` covers LDAP** — `--users`, `--admin-count`, `--groups`,
  `--asreproast`, `--kerberoasting`.
- **`--secretsdump`** — on (Pwn3d!) SMB cred, auto-fires `--sam`/`--lsa`/
  `--ntds`.
- **`--export-json`/`--export-csv`** — structured run summary.
- **Lockout policy detection** with red warning + `--delay` suggestion.
- **`_pick_best_cred`** orders by (pwn3d, local_auth, hash).

### Tier A (fix-the-blockers)
- **`--stop-on-success`**, **(Pwn3d!) highlight**, **pre-flight nxc check**,
  **`--only` / `--exclude`** protocol filters.

### Updater + graphics fixes
- **`scripts/update-nxc.sh`** — install/update the official `nxc` binary
  from GitHub Releases.
- Fixed banner wrap (path truncation + dynamic `shutil.get_terminal_size`)
  and `_match_msg_to_credential` for multi-cred runs.

### Low-power, grouped CLI, air-gapped, restructured README
- **`--low-power`** preset for weak VMs.
- **`--delay` / `--jitter`** for lockout-safe spraying.
- Argparse args grouped into 6 sections + numbered examples epilog.
- `scripts/bundle-airgapped.sh` for offline deployment.
- `Dockerfile` + `.dockerignore`.

### Commands transcript
- **`commands-*.log`** in shell-quoted form (`shlex`), pasteable into
  OSCP reports.

### Initial feature set
- **`--nmap`** pre-scan + SQLite cache.
- **`-H/--hash`**, **`--combo`**, **`-d/--domain`**, **`-k/--kerberos`**,
  **`--null-session`**.
- **`-v/-vv`** / **`-q`** verbosity controls.
- **DC detection** from nxc SMB banner.
- **`--enum`**, **`--modules X,Y`**, **`--bloodhound`** auto-collection
  with per-domain dedup.
