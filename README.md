# NetExec Automator

[![CI](https://github.com/Givaa/netexec-automator/actions/workflows/ci.yml/badge.svg)](https://github.com/Givaa/netexec-automator/actions/workflows/ci.yml)

> Spray [NetExec](https://github.com/Pennyw0rth/NetExec) across **all 10 protocols** in parallel — with nmap pre-scan, hash & Kerberos auth, auto-enum, BloodHound collection, and a shell-pasteable commands transcript for your report.

![NetExec Automator Demo](assets/netexec-automator-demo.gif)

```bash
# The fastest possible "do everything" command on an internal network
python3 netexec-automator.py -t 10.10.10.0/24 --combo loot.txt \
    --nmap --null-session --enum --bloodhound -v
```

---

## Contents

- [Why](#why)
- [Quick Start](#quick-start)
- [Features](#features)
- [Install](#install)
  - [Standard](#standard)
  - [Air-gapped bundle (offline)](#air-gapped-bundle-offline)
  - [Docker (offline-friendly)](#docker-offline-friendly)
- [Usage](#usage)
  - [Authentication options](#authentication-options)
  - [Nmap pre-scan & cache](#nmap-pre-scan--cache)
  - [Auto post-exploitation](#auto-post-exploitation)
  - [Performance & low-power VMs](#performance--low-power-vms)
  - [Output, verbosity, and the commands transcript](#output-verbosity-and-the-commands-transcript)
- [Combo file format](#combo-file-format)
- [CLI reference](#cli-reference)
- [Tuning constants](#tuning-constants)
- [Disclaimer](#disclaimer)

---

## Why

`nxc` is great for a single (protocol, target, cred) triple, but on a real engagement you want to fan out across many protocols × many hosts × many credentials, capture only the real findings, skip dead hosts, document every command for the report, and pivot into post-exploit (BloodHound, SMB enum, modules) without doing it by hand.

**NetExec Automator does that in one command.** It's a single Python file (stdlib only) — drop it next to `nxc` and you're done.

---

## Quick Start

```bash
# 1. Single target, single credential — quickest possible run
python3 netexec-automator.py -t 10.10.10.5 -u admin -p 'Password123!'

# 2. File-based spray with nmap pre-scan (skips dead hosts & closed-port protocols)
python3 netexec-automator.py -t targets.txt -u users.txt -p passwords.txt --nmap

# 3. Combo file (mixed user:password + user:hash auto-detected per line)
python3 netexec-automator.py -t targets.txt --combo loot.txt --nmap

# 4. Pass-the-hash with explicit domain
python3 netexec-automator.py -t dc01 -u administrator \
    -H 8846f7eaee8fb117ad06bdd830b7586c -d corp.local

# 5. Full pwn chain — pre-scan, spray, post-exploit, BloodHound, verbose for the report
python3 netexec-automator.py -t 10.10.10.0/24 --combo loot.txt --nmap \
    --null-session --enum --modules spider_plus,gpp_password --bloodhound -v

# 6. Low-power profile (small VM, 4GB RAM, slow link) — 3 workers, longer timeouts, paced
python3 netexec-automator.py -t targets.txt --combo loot.txt --nmap --low-power

# 7. Recon only — get open ports per host, no auth attempts
python3 netexec-automator.py -t 10.10.10.0/24 -u x -p x --scan-only
```

`python3 netexec-automator.py --help` shows every flag, grouped by purpose, with examples.

---

## Features

| Area | What you get |
|------|-------------|
| **Protocols** | SMB, SSH, LDAP, FTP, WMI, WinRM, RDP, VNC, MSSQL, NFS — plus `--local-auth` variants for SMB/WMI/WinRM/RDP/MSSQL |
| **Credential pairing** | `combination` (cartesian, default), `linear` (1-to-1), or `--combo` file |
| **Auth methods** | Passwords (`-p`), NT or LM:NT hashes (`-H`), Kerberos ccache (`-k`), null session + Guest + anonymous (`--null-session`) |
| **Pre-scan** | `--nmap` discovers open ports first → skips protocols with no open port → skips dead hosts entirely |
| **Cache** | SQLite at `~/.cache/netexec-automator/state.db` — nmap results, DC discoveries, BloodHound dedup |
| **Post-exploit** | `--enum` (shares/users/sessions/loggedon/pass-pol), `--modules X,Y` (nxc `-M`), `--bloodhound` (auto-DC, dedup per domain) |
| **Reporting** | `commands-*.log` with every command in shell-quoted, copy-pasteable form. Loot tree under `loot/<host>/<proto>/<scope>/` |
| **Pacing** | `--low-power` preset for weak VMs; `--delay` + `--jitter` for lockout-safe spraying |
| **Cracking** | `--crack` runs hashcat (or john) on harvested NT (SAM/LSA/NTDS) and Kerberos (AS-REP/TGS-REP) hashes; cracked plaintexts are auto-appended to the grow-combo for the next spray |
| **Output** | Live `[+]` highlights, per-host summary, `-q` for creds-only, `-v`/`-vv` for full debug |
| **DNS PTR** | Each target IP is shown alongside its reverse-DNS hostname when resolvable (`► 10.10.10.5 (dc01.corp.local)`); disable with `--no-resolve` |

---

## Install

### Standard

Requirements:
- Python 3.10+
- [NetExec](https://github.com/Pennyw0rth/NetExec) (`nxc` in `PATH`)
- [nmap](https://nmap.org/) — only for `--nmap` / `--scan-only`
- [bloodhound-python](https://github.com/dirkjanm/BloodHound.py) (`pip install bloodhound`) — only for `--bloodhound`
- [hashcat](https://hashcat.net/) (preferred) or [john](https://www.openwall.com/john/) — only for `--crack`; rockyou is auto-discovered under `/usr/share/wordlists/` and friends

The tool itself is a single Python file with **no external dependencies** (stdlib only):

```bash
git clone https://github.com/Givaa/netexec-automator
cd netexec-automator
python3 netexec-automator.py --help
```

#### Get / update the `nxc` binary

NetExec publishes pre-built standalone binaries (PyInstaller) on its GitHub Releases. The bundled `scripts/update-nxc.sh` will pull the right one for your platform — no `pip`, no Python dependency hell, no sudo required:

```bash
./scripts/update-nxc.sh                  # detect platform, install to ~/.local/bin/nxc
./scripts/update-nxc.sh --check          # dry-run: show what would be downloaded
./scripts/update-nxc.sh --prefix /usr/local/bin   # system-wide install
./scripts/update-nxc.sh --tag v1.5.0     # pin to a specific release
./scripts/update-nxc.sh --force          # reinstall even if version matches
```

The script walks recent releases until it finds one with an asset matching your OS (`nxc-ubuntu-latest.zip` / `nxc-macOS-latest.zip` / `nxc-windows-latest.zip`) — handy when the very latest tag ships no binary. Idempotent: re-running when you're already up-to-date is a no-op. On macOS it also strips the Gatekeeper quarantine attribute so the binary runs on first launch.

### Air-gapped bundle (offline)

On a build host **with** internet:

```bash
./scripts/bundle-airgapped.sh
# → dist/netexec-automator-airgapped-YYYYMMDD.tar.gz
```

The script bundles:
- `netexec-automator.py` + README + LICENSE
- `wheels/` — pip wheels for `netexec` + `bloodhound` + all transitive deps
- `bin/nxc` — pre-built NetExec Linux x64 binary (fetched from the latest GitHub release, optional)
- `install-offline.sh` — one-shot installer for the target host

On the air-gapped target:

```bash
tar xzf netexec-automator-airgapped-*.tar.gz
cd netexec-automator-airgapped-*
./install-offline.sh                # creates a venv, pip install --no-index, drops nxc in /usr/local/bin
```

Knobs:
- `SKIP_NXC_BINARY=1` — skip the GitHub binary fetch (wheels only)
- `INCLUDE_BLOODHOUND=0` — drop bloodhound-python from the bundle
- `PIP_PLATFORM=manylinux2014_x86_64` — cross-bundle wheels for a different platform

### Docker (offline-friendly)

```bash
# Build on a host with internet
docker build -t netexec-automator:latest .

# Export for offline transfer
docker save netexec-automator:latest | gzip > netexec-automator.tar.gz

# Import on the air-gapped host
gunzip -c netexec-automator.tar.gz | docker load

# Run (--network host so the container can reach internal subnets directly)
docker run --rm -it --network host -v "$PWD":/work netexec-automator \
    -t /work/targets.txt --combo /work/loot.txt --nmap --low-power \
    --loot-dir /work/loot --cmd-log /work/commands.log
```

The image bundles `nxc`, `nmap`, and `bloodhound-python`. Drop with `--build-arg INSTALL_NMAP=0` or `INSTALL_BLOODHOUND=0` if you want a slimmer image.

---

## Usage

### Authentication options

| Source | Required flags | Notes |
|--------|----------------|-------|
| Password | `-u <user\|file> -p <pwd\|file>` | The classic spray |
| Hash (PTH) | `-u <user\|file> -H <hash\|file>` | Auto-skipped on SSH/FTP/VNC/NFS |
| Both | `-u … -p … -H …` (combination mode only) | Full cartesian product |
| Combo file | `--combo file.txt` | Mutually exclusive with `-u/-p/-H` |
| Kerberos | `-u … -k -d <domain>` | Requires valid ccache via `KRB5CCNAME` |
| Anonymous quick-wins | `--null-session` | Adds `""`/`Guest:''`/`anonymous:''` |

You can combine `--null-session` with any of the others to prepend the cheap wins.

**Domain auth** (`-d corp.local`) is appended automatically as `-d` for `nxc`, and *suppressed* on `--local-auth` runs to keep nxc happy.

### Nmap pre-scan & cache

With `--nmap`, the tool runs `nmap -Pn -n --open -p <known-ports> -T4` against each target before any auth attempt. Only protocols whose mapped ports are open are then tested. CIDR/range specs are expanded by nmap — dead hosts disappear entirely.

| Protocol | Probed ports |
|----------|--------------|
| SMB | 445, 139 |
| SSH | 22 |
| LDAP | 389, 636 |
| FTP | 21 |
| WMI | 135 |
| WinRM | 5985, 5986 |
| RDP | 3389 |
| VNC | 5900 |
| MSSQL | 1433 |
| NFS | 2049 |

Results land in `~/.cache/netexec-automator/state.db`. Subsequent runs hit the cache (instant) until `--cache-ttl` (default 24h) expires, or you pass `--no-cache` for a forced re-scan. Dead hosts are cached too (sentinel row) so re-running a `/24` doesn't re-probe known-unreachable IPs.

### Auto post-exploitation

When `--enum`, `--modules`, or `--bloodhound` are on, a follow-up phase runs **per host** as soon as the spray completes — without interfering with the live progress bar.

**`--enum` (SMB)** runs against the strongest valid SMB cred (domain auth > local, password > hash):

| Probe | Flag | Output |
|-------|------|--------|
| Shares | `--shares` | `loot/<host>/smb/<scope>/shares.txt` |
| Users | `--users` | `loot/<host>/smb/<scope>/users.txt` |
| Sessions | `--sessions` | `loot/<host>/smb/<scope>/sessions.txt` |
| Logged-on | `--loggedon-users` | `loot/<host>/smb/<scope>/loggedon.txt` |
| Password policy | `--pass-pol` | `loot/<host>/smb/<scope>/pass-pol.txt` |

**`--modules X,Y`** runs any nxc `-M` module, comma-separated, into `loot/<host>/smb/<scope>/module-<name>.txt`.

**`--bloodhound`** runs after all hosts have been sprayed. For each AD domain seen in nxc SMB banners:
1. Identify DC candidates (host advertised the domain AND has LDAP+SMB open, when `--nmap` is on).
2. Pick the best domain credential available.
3. Run `bloodhound-python -c All --zip` once → `loot/bloodhound/<domain>/<timestamp>/` (zip + stdout/stderr logs).
4. Persist the successful run in SQLite so the same domain is **never** recollected within `--bloodhound-ttl` (default 24h), even across runs and unrelated credential pairs. `--bloodhound-force` overrides.

### Auto-cracking harvested hashes

When `--crack` is on, every hash the post-exploit phase pulls out gets immediately offered to a cracker (hashcat by default, john as fallback):

| Hash source | nxc flag | Hashcat mode | What lands in loot/ |
|-------------|----------|--------------|---------------------|
| SAM / LSA / NTDS | `--sam` / `--lsa` / `--ntds` (via `--secretsdump`) | `-m 1000` (NT) | `loot/cracked/nt-hashes.txt` + cracked plaintexts |
| AS-REProasting | `--asreproast` (via `--enum`) | `-m 18200` | `loot/<host>/ldap/domain/asreproast.txt` + cracks |
| Kerberoasting | `--kerberoasting` (via `--enum`) | `-m 13100` | `loot/<host>/ldap/domain/kerberoasting.txt` + cracks |

The wordlist is auto-discovered under:
1. `/usr/share/wordlists/rockyou.txt` (Kali, decompressed)
2. `/usr/share/wordlists/rockyou.txt.gz` (Kali, raw — auto-decompressed on first use)
3. `/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt`
4. `~/wordlists/rockyou.txt`

Pass `--wordlist /path/to/file` to override, or download rockyou with:
```bash
mkdir -p ~/wordlists
wget -O ~/wordlists/rockyou.txt \
    https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
```

**The killer move**: every cracked plaintext is appended to the grow-combo file in `user:password` form. Pass that file as `--combo` next run and you're spraying the freshly-cracked accounts across the whole network — lateral movement, automated, end-to-end.

```bash
# First run — pwn one host, dump SAM, crack with rockyou, append plaintexts to combo
python3 netexec-automator.py -t 10.10.10.0/24 --combo seed.txt \
    --nmap --null-session --enum --secretsdump --crack -v

# Second run — spray the harvested+cracked creds across the rest of the network
python3 netexec-automator.py -t 10.10.10.0/24 \
    --combo loot/auto-grown-creds.txt --nmap -v
```

Knobs:
- `--cracker {hashcat,john,auto}` — pick the cracker (default: auto = hashcat if present)
- `--crack-rules /usr/share/hashcat/rules/best64.rule` — apply hashcat rules
- `--crack-timeout 600` — max seconds per attack (default 10 min per hash type)

### Performance & low-power VMs

If your Kali VM gets crushed by 15 parallel `nxc` subprocesses, use the preset:

```bash
python3 netexec-automator.py -t targets.txt --combo loot.txt --nmap --low-power
```

`--low-power` sets: `workers=3`, `max-retry=1`, `netexec-timeout=45s`, `subprocess-timeout=60s`, `delay=0.5s`. Each individual knob can also be overridden:

```bash
# Conservative spray to dodge account-lockout
python3 netexec-automator.py -t … -u users.txt -p passwords.txt --delay 2 --jitter 3

# Manual tuning on top of low-power
python3 netexec-automator.py -t … --combo … --nmap --low-power -w 5 --delay 0
```

### Output, verbosity, and the commands transcript

**Verbosity:**

| Mode | Flag | Shows |
|------|------|-------|
| Quiet | `-q` | Only valid credentials (one per line) — pipe-friendly |
| Normal | *(default)* | Banner, live `[+]` finds, timeout skips, per-host summary |
| Verbose | `-v` | + each nxc command before execution, failed-auth `[-]` lines, cache hit/miss, DC candidate detection |
| Debug | `-vv` | + raw `[*]` info lines, nmap raw stats |

**Commands transcript** (OSCP-friendly): every command the tool fires — nmap, each nxc auth attempt, post-exploit `--shares`/`--users`/etc., nxc `-M` modules, `bloodhound-python` — is appended to `commands-HH-MM-SS-mmm.log` in **shell-quoted form** (passwords with spaces/quotes/`$`/backticks and usernames with backslashes all correctly escaped):

```
# NetExec Automator — commands transcript
# Started: 2026-05-24T15:43:35

# 2026-05-24T15:43:35 [nmap] target=10.10.10.0/24
nmap -Pn -n --open -p 445,139,22,389,636,21,135,5985,5986,3389,5900,1433,2049 -T4 -oX - 10.10.10.0/24

# 2026-05-24T15:43:51 [SMB (domain)] target=10.10.10.5
nxc smb 10.10.10.5 -u svc -H 8846f7eaee8fb117ad06bdd830b7586c -d corp.local --timeout 30 --log 15-43-35-713.txt

# 2026-05-24T15:44:18 [bloodhound corp.local] target=10.10.10.5
bloodhound-python -c All -u 'dom\admin' -d corp.local -dc 10.10.10.5 -ns 10.10.10.5 --zip -p 'P@ss w0rd '"'"'$x`'
```

Override the path with `--cmd-log /path/to/file`. Disable with `--no-cmd-log`.

---

## Status icons & error handling

Every post-exploit and live action uses one of these icons; the meaning is **stable** across the whole tool:

| Icon | Meaning |
|------|---------|
| ✔ green | action produced real, actionable data |
| ⊘ yellow | ran cleanly but nothing to show (e.g. `STATUS_ACCESS_DENIED`, `--ntds` on non-DC, no domain cred for BloodHound) — **expected, not a bug** |
| ✘ red | real failure: subprocess exit ≠ 0, I/O error, cracker explosion |
| ⚠ yellow | warning: feature degraded/disabled, lockout risk, flag combo can't produce results |
| ⏱ yellow | network-level timeout |
| ↷ grey | deliberately skipped (filter, dedup, `--stop-on-success`) |
| 💀 red | `(Pwn3d!)` — credential grants admin on host |
| 🧪 green | hashes harvested |
| 🔓 cyan | cracking activity |
| 🩸 cyan | DC discovery / BloodHound |
| ⚡ green | valid credential (live) |

**`--strict`**: exit code 1 if any real error occurred during the run. A final diagnostic block on `stderr` lists up to 20 errors with their context (host, action, reason). Useful in CI / piped scripts:

```bash
python3 netexec-automator.py -t targets.txt --combo loot.txt --nmap --enum --strict
echo "exit code: $?"   # 0 = clean, 1 = something needs attention
```

Warnings and errors go to **stderr**, live findings and the per-host summary stay on **stdout**, so piping behaves predictably:

```bash
python3 netexec-automator.py … -q 2>/dev/null     # cred lines only, no warnings noise
python3 netexec-automator.py … 2>errors.log       # capture all warnings/errors separately
```

The tool also runs a **boot-time validation** of your flag combination — if you enable `--crack` without a hash source (`--secretsdump` / `--enum`), or `--modules` with `--only ldap`, you get a yellow ⚠ explaining why nothing will happen, rather than silent confusion at the end of the run.

## Combo file format

```
# Lines starting with # are comments. Blank lines are ignored.
administrator:S3cr3tP@ssword!
svc_backup:8846f7eaee8fb117ad06bdd830b7586c
legacy_user:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
guest:
domain\dev:Spring2025!
```

The secret on each line is auto-detected:
- **32 hex chars** → NT hash (`-H`)
- **32:32 hex chars** → LM:NT hash (`-H lm:nt`)
- anything else → password (embedded `:` and surrounding whitespace are preserved)

---

## CLI reference

`python3 netexec-automator.py --help` for the authoritative help. Flags are grouped: **target · credentials · nmap pre-scan & cache · post-exploitation · performance & pacing · output & logging**.

Most-used flags at a glance:

| Flag | Default | What it does |
|------|---------|-------------|
| `-t, --target` | *(required)* | IP/hostname/CIDR or path to a targets file |
| `--no-resolve` | off | Skip reverse-DNS PTR lookup of target IPs in the on-screen output |
| `--resolve-timeout` | `2.0` | Per-host DNS PTR lookup timeout in seconds |
| `-u, --user` | — | Username or path to users file |
| `-p, --password` | — | Password or path to passwords file |
| `-H, --hash` | — | NT or LM:NT hash, single or file |
| `-d, --domain` | — | Active Directory domain |
| `-k, --kerberos` | off | Use ccache via `KRB5CCNAME` |
| `--combo` | — | `user:secret` combo file (auto-detects pwd vs hash) |
| `--null-session` | off | Prepend null/Guest/anonymous attempts |
| `--nmap` | off | Port pre-scan; only spray protocols with open ports |
| `--scan-only` | off | Pre-scan only, no auth attempts |
| `--no-cache` | off | Bypass SQLite cache |
| `--cache-ttl` | 86400 | Nmap cache validity in seconds |
| `--cache-path` | `~/.cache/...` | Custom SQLite cache path (isolate parallel/CI runs) |
| `--enum` | off | SMB enum probes into `loot/` |
| `--modules` | — | Comma-separated nxc `-M` modules |
| `--bloodhound` | off | Auto-collect BloodHound per discovered domain |
| `--bloodhound-force` | off | Bypass per-domain dedup |
| `--bloodhound-ttl` | 86400 | Per-domain dedup window |
| `--loot-dir` | `loot/` | Root for enum/modules/bloodhound output |
| `--secretsdump` | off | On `(Pwn3d!)` cred, auto-dump SAM/LSA/NTDS + grow combo |
| `--grow-combo` | auto | Where to append harvested/cracked creds (default `<loot>/auto-grown-creds.txt`) |
| `--crack` | off | Auto-crack NT (SAM/LSA/NTDS) + Kerberos (AS-REP/TGS-REP) hashes |
| `--wordlist` | auto | Wordlist path (default: rockyou auto-discovery) |
| `--cracker` | `auto` | `hashcat` / `john` / `auto` |
| `--crack-rules` | — | Hashcat rules file (e.g. `best64.rule`) |
| `--crack-timeout` | 600 | Per-attack timeout in seconds |
| `--export-json` | — | Structured run summary in JSON |
| `--export-csv` | — | Valid creds in CSV format |
| `--low-power` | off | Preset: 3 workers, retry=1, longer timeouts, small delay |
| `-w, --workers` | 15 | Parallel threads |
| `--delay` | 0 | Sleep between credential attempts (seconds) |
| `--jitter` | 0 | Random additional sleep (0..jitter) |
| `--netexec-timeout` | 30 | Per-attempt nxc `--timeout` |
| `--subprocess-timeout` | 45 | Hard Python timeout per nxc call |
| `--max-retry` | 3 | Skip a protocol after N consecutive timeouts |
| `-o, --output` | timestamped | nxc `--log` file path |
| `--cmd-log` | timestamped | Shell-quoted commands transcript |
| `--no-cmd-log` | off | Disable the transcript file |
| `-v, --verbose` | 0 | `-v` commands+errors, `-vv` raw output |
| `-q, --quiet` | off | Only print valid creds |
| `--strict` | off | Exit 1 if any real error occurred (CI-friendly) |
| `-m, --mode` | `combination` | `combination` (cartesian) or `linear` (1-to-1) |

---

## Tuning constants

Defaults at the top of `netexec-automator.py`. The CLI flags above override all of these; edit only if you need different baseline values:

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_RETRY` | `3` | Consecutive connectivity timeouts before skipping a protocol |
| `NETEXEC_TIMEOUT` | `30` | Per-attempt nxc `--timeout` (seconds) |
| `SUBPROCESS_TIMEOUT` | `45` | Python-level hard timeout per nxc call (seconds) |
| `DEFAULT_WORKERS` | `15` | Thread pool size (10 protocols + 5 local-auth variants) |
| `LOW_POWER_PROFILE` | dict | Workers/retry/timeout/delay applied by `--low-power` |
| `PROTOCOL_PORTS` | dict | Protocol → TCP ports nmap probes |
| `CACHE_DEFAULT_TTL` | `86400` | Cache validity (seconds) |
| `BLOODHOUND_TIMEOUT` | `600` | Hard timeout per `bloodhound-python` invocation |

---

## Development

```bash
# Run the test suite
python3 -m venv .venv && source .venv/bin/activate
pip install pytest
pytest tests/ -v
```

Tests cover parsers (hash detection, combo file, Pwn3d, lockout/SAM regex), the command builder (domain suppression on `--local-auth`, Kerberos only on supported protocols), the credential matcher (password / hash / null-session / Guest), protocol filters, the TOML loader, and DNS SRV parsing. Add a test before fixing a bug.

CI runs the same suite on Python 3.10–3.13 and lints `scripts/*.sh` on every push and PR. See [.github/workflows/ci.yml](.github/workflows/ci.yml).

To refresh the demo GIF, install `asciinema` and `agg` and run `./scripts/record-demo.sh` — it walks you through the recording, then renders the cast to the path linked in this README.

## Disclaimer

For authorized security testing only. Always ensure you have explicit written permission before testing credentials against any target. Unauthorized access to computer systems is illegal.
