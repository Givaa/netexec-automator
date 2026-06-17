# Changelog

All notable changes to this project are documented here.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/),
and dates are ISO 8601. Tags follow semver; entries grouped by tag below.

---

## [Unreleased]

### Fixed — domain creds wrongly shown under "local" in `--show`
- Attempts were tagged in the cache with the `-d` value only, so without `-d`
  (the common case — the domain is discovered from the SMB banner) domain-auth
  creds had a NULL domain and fell into the "local / no domain" bucket. Now a
  domain-auth attempt is tagged with the host's discovered domain (`host_domain`,
  falling back to `-d`); local auth records no domain. `--show` also groups by
  the auth **scope** — local-auth → local bucket, domain-auth → its domain (or
  "domain (unknown)") — so a domain cred can never appear under local, even for
  rows cached before this fix.

### Added — scoped reset + time-clustered loot view
- **`--reset DOMAIN`** wipes only that domain's loot / DC / BloodHound records
  (`--reset` with no value still wipes everything); **`--reset-except DOMAIN`**
  wipes everyone else and keeps that one. Use `--reset local` for the
  domain-less local creds. Port scans (`host_ports`) have no domain, so scoped
  resets leave them be. `--reset` and `--reset-except` are mutually exclusive.
- **`--show` now clusters domain-less local creds by the day they were found**
  (with the time per entry), while domain creds stay grouped by domain — so a
  single engagement's local pwns sit together. `list_valid()` now also returns
  each row's `attempted_at` timestamp.

### Changed — `-p` auto-detects hashes mixed into the password list
- The `-p` pool now auto-detects NT (32 hex) and LM:NT (32:32 hex) entries and
  sprays them as **pass-the-hash**, using the same rule as `--combo`. So a
  single `-p` list mixing passwords and hashes works: every user is tried with
  all passwords **and** all hashes. (`-H` stays the explicit, validated hash
  list.) The detection is now a shared `_make_secret_cred` helper used by both
  `--combo` and `-p`.

### Added — `--combo-spray` + host-centric recap
- **`--combo-spray`**: with `--combo`, treat the file's users and secrets as
  pools and spray every secret against every user (cartesian), like
  `-u users -p passwords`, instead of only the 1:1 `user:secret` pairs. Errors
  out if used without `--combo`.
- **Host-centric FINAL REPORT.** The recap now leads with the hosts you fully
  own — "OWNED — full admin on N host(s)", each as "💀 host — you have admin
  here" with its admin creds — then lists hosts where creds hit but you're not
  admin yet ("VALID CREDS — N host(s), no admin yet"), grouped by host.

### Fixed — colons in cracked passwords
- The hashcat/john potfile parser split on the **last** `:`, so a cracked NT
  password containing a colon (e.g. `Sum:mer:25`) was truncated and then
  dropped by the hash-type filter. It now splits on the first colon after the
  32-hex NT hash (Kerberos hashes, which embed colons, still use the last
  colon). Combo-file parsing already split on the first colon — verified and
  locked with a test (passwords with colons are kept whole).

### Changed — nmap-style errors + protocol-aware `--null-session`
- **Friendlier argument errors.** A bad or unknown flag now prints a single
  clear line and points at `--help` (nmap-style) instead of dumping the whole
  usage block. Exit code stays 2.
- **`--null-session` is now protocol-aware.** It still tries null session,
  `Guest:''` and `anonymous:''` on every protocol, and now also tries FTP's
  classic `anonymous:anonymous` and `ftp:ftp` — but only on FTP, so other
  protocols aren't sprayed with FTP noise. Anonymous logins (incl. the new
  `ftp` user) are correctly excluded from the lockout-risk count and labelled
  "anon" in the banner (also fixes a latent `Guest` case-mismatch there).

### Added — loot recall (`--show`) and engagement reset (`--reset`)
- **`--show`**: print the valid credentials already on record (read from the
  SQLite cache), grouped by domain, then exit. Shows `user@host [proto/scope]`
  and `(Pwn3d!)`; secrets are never printed (only the SHA1 hash is stored).
- **`--reset`**: wipe **all** cached state — port scans, tried creds + loot, DC
  discoveries and BloodHound runs — for a clean start on a new domain/context,
  then exit. Supersedes `--clear-tried-cache` (now a hidden deprecated alias
  that still wipes only the tried-creds table).
- **End-of-run loot reminder**: when the cache holds valid creds from *prior*
  runs (beyond what this run found), the FINAL REPORT is followed by a
  by-domain "LOOT ON RECORD" ledger. Skipped when this run is the only source,
  so there's no redundancy with the per-run report.

### Changed — menu & flag cleanup
- The startup menu's separate "Incremental" and "Prior loot" rows are merged
  into one compact **Memory** line (`N tried · M valid · …`), shown only when
  the cache actually holds something.
- Deprecated no-op flags (`--nmap`, `--skip-tried`) and the superseded
  `--clear-tried-cache` are hidden from `--help` (they still work). The
  `--help` examples no longer push the deprecated `--nmap` and now show
  `--show` / `--reset` / `--retry-all` / `--no-nmap`.
- Clarified that every spray tries **both** domain auth and local auth
  (`--local-auth`) for SMB/WMI/WinRM/RDP/MSSQL — already the behaviour, now
  covered by a test and reflected in the menu's `Protocols N (+local auth)`.

### Changed — stateful, incremental discovery & spray
The tool now remembers what it learned across runs and only redoes work on
purpose. Four behaviour changes, each with an explicit opt-out:

- **nmap pre-scan is on by default.** The first run scans open ports per host,
  caches them, and reuses them on later runs (only protocols whose ports are
  open get sprayed). `--no-nmap` restores the old spray-everything behaviour;
  `--nmap` is now a deprecated no-op; `--scan-only` still forces it. nmap-missing
  still degrades gracefully to no pre-scan.
- **Incremental spray is on by default.** Prior `(target, protocol, scope, user,
  secret)` attempts are remembered and skipped, so a 100-credential file isn't
  re-sprayed wholesale every run — only new combinations are tried. Successes /
  `(Pwn3d!)` are always skipped on re-runs; failures stay skipped unless
  `--rerun-after` fires. `--retry-all` (alias `--no-skip-tried`) forces a full
  re-spray; `--skip-tried` is now a deprecated no-op.
- **The cache distinguishes stable from volatile facts.** Open-port sets keep
  the long `--cache-ttl` (24h); a "host dead / no open ports" result now expires
  after the much shorter `--dead-ttl` (1h default). Before trusting a cached-dead
  host, the discovery step re-probes liveness (the stdlib TCP connect) — so a
  host that comes back online is re-scanned at once instead of staying skipped
  for a day (honours `--no-reachability-check`).
- **`--rescan`**: ignore cached scan results for the targets, re-check liveness,
  and re-run nmap from scratch (the fresh result overwrites the cache).
- **Per-IP cache reuse across ranges.** A CIDR up to /20 is expanded and only
  the IPs we don't already know are nmap'd; cached open-port sets and fresh dead
  sentinels are reused, and freshly-scanned results (including dead ones) are
  stored per IP. Larger ranges and nmap dash-ranges fall back to a single full
  nmap.
- **Startup menu shows prior loot.** A "Prior loot" line summarises credentials
  found valid in earlier runs for the current targets (`user@host`, Pwn3d
  flagged), read from the cache. Secrets are never shown — only the hash is
  persisted.
- New cache APIs `invalidate()` and `list_valid()`; `NmapScanner.scan()` accepts
  a list of targets; new `--dead-ttl` / `--rescan` / `--retry-all` flags.

### Fixed
- **`(hostname)` no longer disappears from the live header when `--nmap` is
  off.** The parallel SMB-banner sweep passed an empty ports set to the probe,
  whose "no SMB ports → skip" guard then skipped it, so the host name was never
  resolved on networks without DNS PTR. The sweep now passes `None` ("ports
  unknown, probe anyway").

### Changed — UX, validation, performance polish
- **`logs/` directory by default**: nxc `--log` and the commands transcript
  now land in `./logs/HH-MM-SS-mmm.txt` and `./logs/commands-HH-MM-SS-mmm.log`
  instead of cluttering the cwd. The dir is created lazily; if the cwd is
  read-only the tool falls back to `.` so the run isn't blocked.
- **Fail-fast input validation** (`_validate_args` in `cli.py`): every
  user-supplied path is checked for existence (`--combo`, `--wordlist`,
  `--crack-rules`, `--config`, and `-t / -u / -p / -H` when they look
  path-like) and every numeric flag is range-checked. Failures produce a
  clean `parser.error()` (exit code 2 with a single-line message) instead
  of a mid-spray Python traceback. `--config` parse errors also route
  through `parser.error()` for a uniform UX.
- **Tagline refresh**: argparse description and banner subtitle now read
  `spray 'em all — auto-pwn AD` instead of `auto-pwn AD in one command`.
- **Banner table truncation**: cells with non-path values (e.g.
  `Post-exploit: enum(smb+ldap) · modules=spider_plus,gpp_password,…`)
  used to overflow the column budget on narrow terminals. New
  `_truncate_text` helper counts visible columns (ANSI-stripped + wide-
  emoji aware) and appends an ellipsis when the cell would otherwise slip
  off-grid. The right border now lands at column 72 regardless of input
  length.
- **Reachability TCP pre-check** when `--nmap` is off: single-host targets
  are probed on a short list of common ports (445, 22, 3389, 80, 139); a
  host that rejects every probe is added to `dead_hosts` instead of being
  sprayed for ~15 worker-minutes. CIDR / range specs are never TCP-probed
  (they go through nmap or the full spray path). Opt out with
  `--no-reachability-check`. The probe fires non-blocking connects across
  every resolved address (both families, like `socket.create_connection`'s
  all-addresses fallback) at once via a `selectors` loop and returns on the
  first accept — so a dead host costs ~one timeout instead of
  len(ports) × timeout, and a live host stays instant. Thread-free by
  design: a thread pool would strand losing connect threads (joined at
  interpreter exit, stalling it) that pile up across the per-target
  discovery loop. +5 regression tests cover the all-addresses fallback,
  the parallel-timeout bound, and zero thread leakage.
- **Parallel SMB banner sweep** before the spray: previously each host's
  `_probe_smb_banner` ran serially right before its header was printed,
  adding ~5 s × N hosts of dead wall-clock latency. Now all discovered
  live hosts are probed concurrently (up to 20 workers) so the first
  header appears immediately.
- **SQLite cache runs in WAL mode** (`journal_mode=WAL` +
  `synchronous=NORMAL`): cache readers (spray workers calling `get_fresh` /
  `was_tried`) no longer block the single writer — the prerequisite for
  spraying hosts in parallel off a shared cache. `NORMAL` sync is durable
  enough for a regenerable cache and saves one fsync per commit.
- **`_visible_len` precompiles its ANSI-escape regex** and hoists the
  `re` / `unicodedata` imports out of the per-call path (it runs once per
  banner / table row). Output is byte-identical — purely a per-call cost cut.
- 18 new pytest cases in `tests/test_validation.py` covering: missing
  files for `--combo` / `--wordlist` / `--config` / path-like `-t`,
  range checks (`--workers 0`, `--delay -1`), `--combo` + `-u` mutual
  exclusion, `_truncate_text` semantics including wide-emoji budgeting,
  `logs/` default paths, `--no-cmd-log` disabling, custom `--cmd-log`
  override, `_is_host_reachable` returning False for closed-port hosts,
  `reachability_check` flag plumbing. 166 → 184 total.

### Added — `--exam-safe` module guardrail
- **`--exam-safe`**: refuses to start (clean `parser.error()`, exit code 2)
  when `--modules` contains an automated-exploitation module. The blocklist
  (`EXAM_SAFE_BLOCKLIST` in `constants.py`) covers CVE-exploit and auth-coercion
  modules — `zerologon`, `nopac`, `petitpotam`, `printnightmare`, `ms17-010`,
  `smbghost`, `dfscoerce`, `shadowcoerce`, `coerce_plus` — while leaving
  enumeration/collection modules (`spider_plus`, `gpp_password`, …) allowed.
  Intended for OSCP-style exams where automated exploitation is prohibited.
  Matching is case-insensitive and treats `-`/`_` as equivalent, so
  `MS17-010` and `ms17_010` both trip the gate. The offending module names
  are echoed back in the error so you know exactly what to drop. No effect
  unless the flag is set. Four tests in `test_validation.py` cover the
  refuse/allow/normalization/inert-without-flag paths.

### Fixed — BloodHound + domain-wide LDAP enum
- **`--bloodhound` now picks the most-privileged credential** discovered
  during the spray, not whichever cred happened to validate first. The
  old selector iterated `self.valid_creds` linearly and returned the
  first domain-auth match — meaning a non-admin user often got picked
  over an admin Pwn3d! on a different host of the same domain. New
  helper `_pick_best_domain_cred(domain)` reuses `_pick_best_cred()`
  so the (Pwn3d!) > domain-auth > password ranking is consistent with
  the per-host post-exploit selector.
- **BloodHound now receives the DC FQDN as `-dc`**, falling back to
  the IP when the NetBIOS name isn't known. `-ns` stays as the IP
  (bloodhound-python uses it as a nameserver for LDAP target lookups).
  Fixes BloodHound collection on Kerberos-strict domains where the
  ticket TGT lookup needs the hostname, not the IP.
- **`bloodhound-python` -u value is now stripped of the `DOMAIN\\` prefix.**
  Before, a credential captured as `corp\\administrator` was passed
  verbatim and the tool errored out; now only the bare username is sent
  (`administrator`), with `-d corp.local` carrying the domain.
- **LDAP enum (`--enum --asreproast --kerberoasting` etc.) is now a
  domain-wide pass at end-of-run**, not a per-host one. Before, the
  enum used whichever cred validated on that single host — which often
  meant running asreproast as a low-priv user when an admin was sitting
  in `valid_creds` for another host on the same domain. Now
  `_run_ldap_enum_pass()` iterates discovered domains, picks the best
  cred across the entire run, queries the best DC for it, and writes
  output to `loot/domain/<domain>/ldap/`.
- The on-screen banner for both passes now surfaces the chosen cred
  with a `(Pwn3d!)` or `(non-admin)` marker, so the operator can see
  immediately whether the right account is being used:

      🩸 BloodHound Collection
      ▸ corp.local via DC01.corp.local (10.10.10.5) [smb_banner] as administrator (Pwn3d!)

- 13 new pytest cases in `tests/test_bloodhound.py` covering: prefix
  stripping (`corp\\admin` → `admin`), FQDN-preferred-over-IP for `-dc`
  while `-ns` stays IP, hash auth path, `_pick_best_domain_cred` Pwn3d
  priority, local-auth exclusion from domain creds, DNS-SRV > cache >
  banner fallback chain in `_pick_dc_for_domain`, `_dc_fqdn` from
  captured NetBIOS name. 153 → 166 total.

### Added — Incremental spray (`--skip-tried`)
- **`--skip-tried`**: persist every (target, protocol, scope, user, secret)
  attempt to the SQLite cache and skip combinations seen in prior runs.
  Lets you add new users / passwords to your wordlists and re-spray
  only the new combinations against a wide CIDR without paying the cost
  of the previous run again. Successes (and any `(Pwn3d!)` line) are
  **always** skipped on re-runs.
- **`--rerun-after <SECONDS>`**: re-attempt past *failures* older than
  this many seconds. Default `0` = never re-attempt failures.
- **`--clear-tried-cache`**: wipe the `tried_creds` table from the cache
  and exit. Use this when you want `--skip-tried` to start fresh.
- New `tried_creds` SQLite table (PK: target, protocol, local_auth,
  user, secret_hash). Only SHA1 of the secret is stored — **never the
  plaintext password**. user is a separate column so the same password
  used by two users is correctly tracked as two attempts.
- Thread-safety: HostCache now opens the SQLite connection with
  `check_same_thread=False` and serializes writes with an internal lock,
  because record_attempt() is invoked from the spray worker threads.
- Banner gets a new `Incremental` row when `--skip-tried` is on, showing
  the prior-entry count and the rerun policy. The FINAL REPORT gains
  a `SKIPPED — ALREADY TRIED (N)` block when any combinations were
  skipped during the run, with a pointer to the cache path.
- 13 new pytest cases in `tests/test_skip_tried.py` covering: cache
  round-trip, success-always-skipped, stale-failure retry with
  `--rerun-after`, PK upsert (no duplicates), local-auth as part of the
  key, fingerprint stability + plaintext-leak guard, --skip-tried opens
  the cache even without --nmap, default off. 140 → 153 total.

### Added — Installable as a real binary on Kali / Debian / Ubuntu / macOS
- **`pyproject.toml`** (hatchling backend) with two console entry points:
  - `netexec-automator` (full name)
  - `nxa` (short alias for daily use)
  Standard Python packaging — `pip install .` or `pipx install .` from the
  repo root produces both shortcuts in `~/.local/bin/`.
- **`scripts/install.sh`** opinionated installer: detects pipx first
  (preferred — isolated venv, no PEP 668 hassles), falls back to
  `pip install --user` with `--break-system-packages` when needed on newer
  Debian/Kali. Supports `--uninstall` and `--force-pip` overrides, prints
  a PATH hint when `~/.local/bin` isn't picked up yet.
- **`scripts/build-binary.sh`** — PyInstaller wrapper for a single
  ~50 MB standalone `nxa` binary that embeds the Python interpreter
  (useful for ultra-portable / air-gapped scenarios). `--install <prefix>`
  drops the binary in `/usr/local/bin/` and adds a `netexec-automator`
  symlink. Build venv cached under `.pyinstaller-venv/`.
- `update-nxc.sh` is now bundled as **package data** via
  `[tool.hatch.build.targets.wheel.force-include]` so `nxa --update-nxc`
  keeps working after a pipx install (the script lives in the package
  directory rather than next to the source repo).
- `_find_update_nxc_script()` resolves the script across both layouts
  (repo and pipx install), with a curl-from-github fallback hint in the
  error message when neither is available. New pytest case in
  `test_tier_c.py` to lock in repo-layout discovery.

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
