# NetExec Automator

**NetExec Automator** takes your targets, users, and passwords (single values or files) and blasts them across all 10 nxc protocols in parallel — with local auth variants included. Choose between **combination** (all user×password pairs) or **linear** (index-matched pairs) credential pairing. You get live hits as they come in, automatic timeout skipping, and a clean summary at the end.

![NetExec Automator Demo](assets/netexec-automator-demo.gif)

**Workflow: find creds → add to lists → re-scan → repeat.**

```bash
# Initial scan with known creds (combination mode — all user×password pairs)
python3 netexec-automator.py -t targets.txt -u users.txt -p passwords.txt

# Found svc_backup:Summer2025! in a config file? Add it and re-scan
echo 'svc_backup' >> users.txt
echo 'Summer2025!' >> passwords.txt
python3 netexec-automator.py -t targets.txt -u users.txt -p passwords.txt

# Have known user:password pairs? Use linear mode (1-to-1 index matching)
python3 netexec-automator.py -t targets.txt -u users.txt -p passwords.txt -m linear

# Got a new subnet? Add those targets and go again
echo '10.10.20.0/24' >> targets.txt
python3 netexec-automator.py -t targets.txt -u users.txt -p passwords.txt
```

## Features

- **10 protocols** — SMB, SSH, LDAP, FTP, WMI, WinRM, RDP, VNC, MSSQL, NFS
- **Local auth variants** — Automatically tests `--local-auth` for SMB, WMI, WinRM, RDP, MSSQL
- **Credential pairing modes** — `combination` (cartesian product, default) or `linear` (index-matched 1-to-1 pairs)
- **Parallel execution** — 15 concurrent workers by default (one per protocol/auth-type)
- **Live findings** — Valid credentials (`⚡`) and timeout skips (`⏱`) printed in real-time
- **Auto-skip** — Protocols with consecutive connectivity timeouts are skipped to save time
- **Clean output** — Parsed nxc output, grouped by protocol, with a final credential summary
- **Progress bar** — Real-time tracking per individual nxc command
- **File input** — Accepts single values or newline-separated files for targets, users, and passwords
- **Nmap pre-scan (opt-in)** — `--nmap` discovers open ports first and only sprays protocols whose ports are actually open. Massive speedup on wide CIDRs and dead hosts.
- **SQLite cache** — Pre-scan results are cached in `~/.cache/netexec-automator/state.db` with configurable TTL (default 24h), so repeat runs are instant.
- **NTLM hash auth (`-H`)** — Pass-the-hash with NT or LM:NT format. Accepts single hash or file. Auto-skipped on protocols that don't support it (SSH/FTP/VNC/NFS).
- **Combo files (`--combo`)** — Single `user:secret` file with per-line auto-detection: passwords, NT hashes, and LM:NT hashes mixed freely. Comments (`#`) and blank lines supported.
- **Domain auth (`-d`)** — Explicit domain flag, automatically suppressed on `--local-auth` runs.
- **Kerberos (`-k`)** — Use existing ccache (`KRB5CCNAME`) for ticket-based auth on SMB/LDAP/WMI/WinRM/MSSQL.
- **Null session + Guest + anonymous (`--null-session`)** — Tries `""`/`Guest`/`anonymous` with empty passwords as cheap quick-wins before the main spray.
- **Auto post-exploitation (`--enum`, `--modules`)** — On any valid SMB cred, runs `--shares`/`--users`/`--sessions`/`--loggedon-users`/`--pass-pol` and any nxc `-M` modules, saving output under `loot/<host>/smb/<scope>/`.
- **Auto-BloodHound (`--bloodhound`)** — Detects the AD domain from nxc's SMB banner, identifies a DC (LDAP+SMB open or banner-advertised), and invokes `bloodhound-python -c All --zip` once per discovered domain. Output lands in `loot/bloodhound/<domain>/<timestamp>/`.
- **BloodHound dedup** — Persisted to SQLite. The same domain isn't recollected within `--bloodhound-ttl` (default 24h), even across runs and unrelated credential pairs. `--bloodhound-force` to override.
- **Verbosity controls (`-v`/`-vv`/`-q`)** — From silent (only valid creds) to full debug (raw nxc/nmap output, cache hit/miss, per-attempt command dump).

## Requirements

- Python 3.10+
- [NetExec](https://github.com/Pennyw0rth/NetExec) installed and available as `nxc` in PATH
- [nmap](https://nmap.org/) in PATH — only required when using `--nmap` / `--scan-only`
- [bloodhound-python](https://github.com/dirkjanm/BloodHound.py) (`pip install bloodhound`) in PATH — only required when using `--bloodhound`

## Usage

```bash
# Single target, single credential
python3 netexec-automator.py -t 10.10.10.1 -u admin -p 'Password123!'

# File-based inputs — the intended workflow
python3 netexec-automator.py -t targets.txt -u users.txt -p passwords.txt

# Linear mode — each user[i] paired only with password[i]
python3 netexec-automator.py -t targets.txt -u users.txt -p passwords.txt -m linear

# Custom output file and worker count
python3 netexec-automator.py -t 10.10.10.1 -u admin -p pass.txt -o results.txt -w 20

# Smart mode — nmap pre-scan + cache. Skips protocols on closed ports.
python3 netexec-automator.py -t 10.10.10.0/24 -u users.txt -p passwords.txt --nmap

# Recon only — discover open ports without firing any nxc auth attempts
python3 netexec-automator.py -t 10.10.10.0/24 -u x -p x --scan-only

# Pass-the-hash — single NT hash, with explicit domain
python3 netexec-automator.py -t dc01 -u administrator \
    -H 8846f7eaee8fb117ad06bdd830b7586c -d corp.local

# Combo file (mix of passwords + NT hashes + LM:NT hashes, auto-detected)
python3 netexec-automator.py -t targets.txt --combo loot.txt --nmap

# Quick anonymous wins (null session, Guest:'', anonymous:'') before spraying
python3 netexec-automator.py -t targets.txt -u users.txt -p passwords.txt --null-session

# Kerberos auth with an existing ccache
export KRB5CCNAME=/tmp/krb5cc_user
python3 netexec-automator.py -t dc01 -u administrator -p ignored -k -d corp.local

# Full chain — pre-scan, hash spray, post-exploit enum, BloodHound, debug verbosity
python3 netexec-automator.py -t 10.10.10.0/24 --combo loot.txt \
    --nmap --null-session --enum --modules spider_plus,gpp_password \
    --bloodhound -vv

# Only show valid credentials (great for piping or quick triage)
python3 netexec-automator.py -t targets.txt --combo loot.txt --nmap -q
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target IP/hostname or path to targets file | *required* |
| `-u, --user` | Username or path to users file | *(unless --combo or --null-session)* |
| `-p, --password` | Password or path to passwords file | — |
| `-H, --hash` | NT hash (32 hex), LM:NT (32:32 hex), or path to hashes file | — |
| `-d, --domain` | Active Directory domain (added as `-d` to nxc for domain auth) | — |
| `-k, --kerberos` | Use Kerberos auth (requires valid ccache via `KRB5CCNAME`) | `off` |
| `--combo` | Path to user:secret combo file (auto-detects pwd vs NT/LM:NT hash) | — |
| `--null-session` | Also try `null`/`Guest:''`/`anonymous:''` as cheap quick-wins | `off` |
| `-o, --output` | Custom log file path | `HH-MM-SS-mmm.txt` |
| `-w, --workers` | Number of parallel threads | `15` |
| `-m, --mode` | Credential pairing: `combination` (all pairs) or `linear` (index-matched) | `combination` |
| `--nmap` | Pre-scan target ports with nmap and skip protocols on closed ports | `off` |
| `--no-cache` | Bypass the SQLite nmap result cache (only relevant with `--nmap`) | `off` |
| `--cache-ttl` | Seconds nmap cache entries remain valid | `86400` (24h) |
| `--scan-only` | Run nmap discovery only — no auth attempts. Implies `--nmap` | `off` |
| `-v, --verbose` | Increase verbosity (`-v` adds commands + failed-auth lines, `-vv` adds raw nxc/nmap output) | `0` |
| `-q, --quiet` | Print only valid credentials (suppresses banner, per-host headers, summary) | `off` |
| `--enum` | On valid SMB creds, run `--shares`/`--users`/`--sessions`/`--loggedon-users`/`--pass-pol` into `loot/` | `off` |
| `--modules` | Comma-separated nxc `-M` modules to run on valid SMB creds (e.g. `spider_plus,gpp_password`) | — |
| `--bloodhound` | Auto-collect BloodHound (`bloodhound-python -c All --zip`) per discovered AD domain | `off` |
| `--bloodhound-force` | Bypass the per-domain dedup cache and re-run BloodHound | `off` |
| `--bloodhound-ttl` | Dedup window for BloodHound runs per domain (seconds) | `86400` (24h) |
| `--loot-dir` | Root directory for enum/modules/bloodhound output | `loot/` |

### Credential sources — accepted combinations

| Mode | Required flags |
|------|----------------|
| Password spray | `-u <user|file> -p <pwd|file>` |
| Pass-the-hash | `-u <user|file> -H <hash|file>` |
| Both | `-u <user|file> -p ... -H ...` (combination mode only — full cartesian) |
| Combo file | `--combo file.txt` (mutually exclusive with `-u/-p/-H`) |
| Anonymous only | `--null-session` (no `-u` required) |

`--null-session` can be added on top of any of the above to prepend the anonymous quick-wins.

### Combo file format

```
# Lines beginning with # are comments. Blank lines are ignored.
administrator:S3cr3tP@ssword!
svc_backup:8846f7eaee8fb117ad06bdd830b7586c
legacy_user:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
guest:
domain\dev:Spring2025!
```

The secret on each line is auto-detected:
- 32 hex characters → NT hash (`-H`)
- 32:32 hex characters → LM:NT hash (`-H lm:nt`)
- anything else → password (preserves embedded colons and surrounding whitespace)

## Output

The tool produces three sections:

### 1. Live Scan

Findings appear in real-time as protocols are tested:

```
  ► 10.10.10.1

  ⚡ SMB (domain) corp.local\admin:Password123!
  ⚡ LDAP (domain) corp.local\admin:Password123!
  ⏱ SSH (domain) 3 consecutive timeouts — skipping
```

### 2. Detailed Results

After scanning completes, all results are shown grouped by protocol:

```
────────────────────────────────────────────────────────────
  📋 NetExec Automator Results
────────────────────────────────────────────────────────────
    Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:corp.local)

  ✔ SMB (domain)         corp.local\admin:Password123!
  ✘ SMB (local)          DC01\admin:Password123! STATUS_LOGON_FAILURE
  ✔ LDAP (domain)        corp.local\admin:Password123!
  ⏱ SSH (domain)         3 consecutive timeouts — skipped

  ── No response: FTP, VNC, NFS
```

### 3. Summary

A clean list of only the valid credentials:

```
  ✓ VALID CREDENTIALS

    ► SMB (domain)         │ corp.local\admin:Password123!
    ► LDAP (domain)        │ corp.local\admin:Password123!
```

## Credential Pairing Modes

| Mode | Behavior | Example (2 users, 3 passwords) |
|------|----------|-------------------------------|
| `combination` | Cartesian product — every user tested with every password | 2 × 3 = **6 pairs** |
| `linear` | Index-matched — user[i] paired only with password[i] (lists must be equal length) | **not allowed** (lengths differ) |

**combination** (default) is ideal when you have separate wordlists. **linear** is useful when you have known `user:password` pairs (e.g. from a credential dump) and want to test each pair as-is.

## Nmap Pre-scan & Cache

With `--nmap`, the tool runs `nmap -Pn -n --open -p <known-ports> -T4` against each target before any nxc attempt. Only protocols whose mapped ports are open are then tested. CIDR/range specs are expanded by nmap itself — dead hosts disappear entirely.

Port mapping used by the pre-scan:

| Protocol | Ports |
|----------|-------|
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

Results are persisted in `~/.cache/netexec-automator/state.db` (SQLite). Subsequent runs against the same host hit the cache and skip nmap entirely (until `--cache-ttl` expires or `--no-cache` is passed). Dead hosts are also cached, so re-running a `/24` doesn't re-probe known unreachable IPs.

```bash
# First run — nmap probes, results cached
python3 netexec-automator.py -t 10.10.10.0/24 -u users.txt -p passwords.txt --nmap

# Second run — cache hit, no nmap overhead
python3 netexec-automator.py -t 10.10.10.0/24 -u users.txt -p passwords.txt --nmap

# Force fresh scan
python3 netexec-automator.py -t 10.10.10.0/24 -u users.txt -p passwords.txt --nmap --no-cache
```

## Auto Post-Exploitation

When `--enum`, `--modules`, or `--bloodhound` are on, the tool runs a follow-up phase **per host** as soon as the credential spray for that host completes (so it doesn't interfere with the live progress bar).

### `--enum` (SMB)

For each host with a valid SMB credential (best one preferred: domain auth > local auth, password > hash), runs:

| Probe | nxc flag | Output file |
|-------|----------|-------------|
| Shares | `--shares` | `loot/<host>/smb/<scope>/shares.txt` |
| Users | `--users` | `loot/<host>/smb/<scope>/users.txt` |
| Sessions | `--sessions` | `loot/<host>/smb/<scope>/sessions.txt` |
| Logged-on | `--loggedon-users` | `loot/<host>/smb/<scope>/loggedon.txt` |
| Password policy | `--pass-pol` | `loot/<host>/smb/<scope>/pass-pol.txt` |

`<scope>` is `domain` or `local`.

### `--modules`

Any nxc `-M` module name can be passed, comma-separated. Output goes to `loot/<host>/smb/<scope>/module-<name>.txt`.

### `--bloodhound` (auto-DC discovery + collection)

After all hosts are sprayed:
1. Each AD domain seen in nxc SMB banners is recorded with the candidate DCs that exposed it.
2. A host is treated as a likely DC if it advertised the domain **and** has both LDAP (389/636) and SMB (445) open (when `--nmap` is on). Without nmap, the SMB banner advertisement is sufficient.
3. For each unique domain, `bloodhound-python -c All --zip` runs once using the strongest available domain credential. Output is written to `loot/bloodhound/<domain>/<timestamp>/` along with the raw stdout/stderr logs.
4. Successful collections are recorded in the SQLite cache. Subsequent runs against the same domain within `--bloodhound-ttl` (default 24h) are skipped automatically — even across unrelated credential pairs and unrelated hosts. Override with `--bloodhound-force`.

```bash
# First run on /24 — finds creds, identifies DC, collects BloodHound for corp.local
python3 netexec-automator.py -t 10.10.10.0/24 -u users.txt -p passwords.txt --nmap --bloodhound

# Few hours later, sprayed a different cred set — BloodHound is NOT re-collected for corp.local
python3 netexec-automator.py -t 10.10.10.0/24 --combo new_loot.txt --nmap --bloodhound

# Force re-collection (e.g. after major AD changes)
python3 netexec-automator.py -t 10.10.10.0/24 --combo new_loot.txt --nmap --bloodhound --bloodhound-force
```

## Verbosity

| Mode | Flag | Shows |
|------|------|-------|
| Quiet | `-q` | Only valid credentials (one per line) |
| Normal | *(default)* | Banner, live `[+]` finds, timeout skips, per-host summary |
| Verbose | `-v` | + each nxc command before execution, failed-auth `[-]` lines, cache hit/miss, DC candidate detection |
| Debug | `-vv` | + raw `[*]` info lines, nmap result counts |

## Configuration

Constants at the top of the script:

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_RETRY` | `3` | Consecutive connectivity timeouts before skipping a protocol |
| `NETEXEC_TIMEOUT` | `30` | nxc `--timeout` per connection attempt (seconds) |
| `SUBPROCESS_TIMEOUT` | `45` | Python-level safety timeout per nxc command (seconds) |
| `DEFAULT_WORKERS` | `15` | Thread pool size (10 protocols + 5 local auth) |

## Disclaimer

This tool is intended for authorized penetration testing and security assessments only. Always ensure you have explicit written permission before testing credentials against any target. Unauthorized access to computer systems is illegal.
