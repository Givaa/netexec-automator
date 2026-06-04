"""argparse glue, TOML config loader, --update-nxc shortcut, and main()."""

import argparse
import subprocess
import sys
from pathlib import Path

from .automator import NxcAutomator
from .constants import (BOLD, CACHE_DEFAULT_PATH, CACHE_DEFAULT_TTL,
                        CRACK_DEFAULT_TIMEOUT, DEAD_CACHE_DEFAULT_TTL,
                        DEFAULT_WORKERS, EXAM_SAFE_BLOCKLIST,
                        MAX_RETRY, NETEXEC_TIMEOUT, RED, RESET, SUBPROCESS_TIMEOUT,
                        V_DEBUG, V_QUIET, YELLOW, LOW_POWER_PROFILE, DIM)



def parse_mode(value: str) -> str:
    """Validate accepted mode values."""
    mode = value.lower()
    if mode in ("combination", "linear"):
        return mode
    raise argparse.ArgumentTypeError("Mode must be one of: combination, linear")


def _normalize_module(name: str) -> str:
    """Canonicalize an nxc module name for blocklist matching: lowercase and
    treat '-' and '_' as equivalent so 'ms17-010' and 'ms17_010' compare equal."""
    return name.strip().lower().replace("-", "_")


def _nmap_enabled(args) -> bool:
    """The nmap pre-scan is on by default now: --no-nmap opts out, while
    --scan-only (and the deprecated --nmap no-op) keep it on. So it's enabled
    unless the user explicitly passed --no-nmap without --scan-only."""
    return bool(args.scan_only or not args.no_nmap)


def _load_toml_config(path: str) -> dict:
    """Read a TOML config and return a flat dict of CLI-overridable defaults.

    Uses stdlib tomllib (3.11+) when available; falls back to a tiny line parser
    that supports key=value/key="value"/key=true/key=N — enough for the simple
    configs people actually write."""
    try:
        import tomllib
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except ImportError:
        pass
    out: dict = {}
    for raw in Path(path).read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip()
        if v.startswith(("'", '"')) and v.endswith(v[0]):
            v = v[1:-1]
        elif v.lower() in ("true", "false"):
            v = v.lower() == "true"
        else:
            try:
                v = int(v)
            except ValueError:
                try:
                    v = float(v)
                except ValueError:
                    pass
        out[k] = v
    return out


EXAMPLES_EPILOG = """\
examples:
  # 1. Single host, single credential — quickest possible run
  %(prog)s -t 10.10.10.5 -u admin -p 'Password123!'

  # 2. File-based spray across a CIDR with nmap pre-scan (skips dead hosts/protocols)
  %(prog)s -t targets.txt -u users.txt -p passwords.txt --nmap

  # 3. Combo file with mixed passwords + NT/LM:NT hashes (auto-detected per line)
  %(prog)s -t targets.txt --combo loot.txt --nmap

  # 4. Pass-the-hash with explicit domain
  %(prog)s -t dc01 -u administrator -H 8846f7eaee8fb117ad06bdd830b7586c -d corp.local

  # 5. Anonymous quick-wins before the main spray
  %(prog)s -t targets.txt -u users.txt -p passwords.txt --null-session

  # 6. Full chain: pre-scan, spray, post-exploit enum, BloodHound, verbose
  %(prog)s -t 10.10.10.0/24 --combo loot.txt --nmap --null-session \\
           --enum --modules spider_plus,gpp_password --bloodhound -v

  # 7. Recon only — discover open ports without firing any nxc auth attempts
  %(prog)s -t 10.10.10.0/24 -u x -p x --scan-only

  # 8. Low-power profile for VMs / weak hosts — 3 workers, 1 retry, paced
  %(prog)s -t targets.txt --combo loot.txt --nmap --low-power

  # 9. Quiet mode (only valid creds) — handy for piping
  %(prog)s -t targets.txt --combo loot.txt --nmap -q
"""


def _build_parser():
    parser = argparse.ArgumentParser(
        description="NetExec Automator — spray 'em all. Multi-protocol AD pwnage in one command "
                    "(nmap pre-scan, hash/Kerberos auth, auto-enum, secretsdump, hashcat, BloodHound).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EXAMPLES_EPILOG,
    )

    # ----- Meta / one-shot operations -----
    g_meta = parser.add_argument_group("meta")
    g_meta.add_argument("--update-nxc", action="store_true",
                        help="Install/update the official nxc binary via scripts/update-nxc.sh and exit.")
    g_meta.add_argument("--config",
                        help="Load defaults from a TOML config file (CLI flags still win).")

    # ----- Targeting -----
    g_target = parser.add_argument_group("target")
    g_target.add_argument("-t", "--target",
                          help="Target IP/hostname/CIDR, or path to a targets file (one per line).")
    g_target.add_argument("--only",
                          help="Comma-separated protocols to include (e.g. smb,ldap).")
    g_target.add_argument("--exclude",
                          help="Comma-separated protocols to exclude (e.g. vnc,rdp,nfs).")
    g_target.add_argument("--no-resolve", action="store_true",
                          help="Disable reverse-DNS PTR lookup for target IPs in the on-screen output.")
    g_target.add_argument("--resolve-timeout", type=float, default=2.0,
                          help="Per-host DNS PTR lookup timeout in seconds (default: 2.0).")

    # ----- Credentials -----
    g_auth = parser.add_argument_group(
        "credentials",
        "Provide credentials via -u + (-p OR -H), or --combo, or --null-session "
        "(any of these alone is enough)."
    )
    g_auth.add_argument("-u", "--user",
                        help="Username, or path to users.txt.")
    g_auth.add_argument("-p", "--password",
                        help="Password, or path to passwords.txt.")
    g_auth.add_argument("-H", "--hash", dest="nthash",
                        help="NT hash (32 hex), LM:NT (32:32 hex), or path to hashes.txt.")
    g_auth.add_argument("-d", "--domain",
                        help="Active Directory domain (added as -d <domain> to nxc).")
    g_auth.add_argument("-k", "--kerberos", action="store_true",
                        help="Use Kerberos auth (-k). Requires valid ccache via KRB5CCNAME.")
    g_auth.add_argument("--combo",
                        help="Combo file (user:secret per line). Auto-detects password vs NT/LM:NT hash.")
    g_auth.add_argument("--null-session", action="store_true",
                        help="Also probe null session + Guest:'' + anonymous:'' as cheap quick-wins.")
    g_auth.add_argument("-m", "--mode", type=parse_mode, default="combination",
                        metavar="{combination,linear}",
                        help="Credential pairing: combination (cartesian, default) or linear (1-to-1).")

    # ----- Pre-scan -----
    g_scan = parser.add_argument_group("nmap pre-scan & cache")
    g_scan.add_argument("--nmap", action="store_true",
                        help="(Deprecated — the nmap pre-scan is on by default now; this flag is a harmless no-op.)")
    g_scan.add_argument("--no-nmap", action="store_true",
                        help="Disable the nmap pre-scan and spray every protocol on every target "
                             "(the old default). Use where nmap isn't available or wanted.")
    g_scan.add_argument("--scan-only", action="store_true",
                        help="Run nmap discovery only — no nxc attempts. Forces the pre-scan on.")
    g_scan.add_argument("--no-cache", action="store_true",
                        help="Bypass the SQLite nmap-result cache.")
    g_scan.add_argument("--cache-ttl", type=int, default=CACHE_DEFAULT_TTL,
                        help=f"Cache TTL for open-port results in seconds (default: {CACHE_DEFAULT_TTL} = 24h).")
    g_scan.add_argument("--dead-ttl", type=int, default=DEAD_CACHE_DEFAULT_TTL,
                        help=f"Shorter TTL for 'host dead / no open ports' results (default: "
                             f"{DEAD_CACHE_DEFAULT_TTL} = 1h). Dead hosts are also re-probed for "
                             "liveness every run, so a host that comes back online reappears at once.")
    g_scan.add_argument("--rescan", action="store_true",
                        help="Ignore cached scan results for the targets: re-check liveness and "
                             "re-run nmap from scratch (the fresh result overwrites the cache).")
    g_scan.add_argument("--cache-path",
                        help=f"Custom SQLite cache path (default: {CACHE_DEFAULT_PATH}). Use this to "
                             "isolate concurrent / CI runs from each other.")
    g_scan.add_argument("--skip-tried", action="store_true",
                        help="Persist every (target, protocol, scope, user, secret) attempt to the "
                             "SQLite cache and skip it on subsequent runs. Lets you add new users/"
                             "passwords to the wordlists and re-run only the new combinations. "
                             "Successes (and (Pwn3d!) lines) are always skipped on re-runs; "
                             "failures stay skipped unless --rerun-after fires.")
    g_scan.add_argument("--rerun-after", type=int, default=0, metavar="SECONDS",
                        help="With --skip-tried: re-attempt past *failures* older than this many "
                             "seconds (default: 0 = never re-attempt failures). Successes are still "
                             "always skipped.")
    g_scan.add_argument("--clear-tried-cache", action="store_true",
                        help="Wipe the tried_creds table from the cache and exit. Use this when "
                             "you want --skip-tried to start fresh.")
    g_scan.add_argument("--no-reachability-check", action="store_true",
                        help="Skip the stdlib TCP-connect reachability probe done when --nmap is off. "
                             "By default a quick probe to common ports decides whether a single-host "
                             "target is alive; CIDR / range specs are never probed (they go through nmap "
                             "or full spray).")

    # ----- Post-exploitation -----
    g_post = parser.add_argument_group("post-exploitation (runs only on valid creds)")
    g_post.add_argument("--enum", action="store_true",
                        help="Run --shares/--users/--sessions/--loggedon-users/--pass-pol into loot/.")
    g_post.add_argument("--modules",
                        help="Comma-separated nxc -M modules (e.g. spider_plus,gpp_password,lsassy).")
    g_post.add_argument("--exam-safe", action="store_true",
                        help="Refuse to start if --modules contains an automated-exploitation module "
                             "(zerologon, nopac, petitpotam, printnightmare, ms17-010, smbghost, "
                             "dfscoerce, shadowcoerce, coerce_plus). Use during OSCP-style exams where "
                             "automated exploitation is prohibited.")
    g_post.add_argument("--bloodhound", action="store_true",
                        help="Auto-collect BloodHound (-c All --zip) per discovered AD domain.")
    g_post.add_argument("--bloodhound-force", action="store_true",
                        help="Re-collect BloodHound even if a recent successful run exists for the domain.")
    g_post.add_argument("--bloodhound-ttl", type=int, default=CACHE_DEFAULT_TTL,
                        help=f"Per-domain dedup window for BloodHound (default: {CACHE_DEFAULT_TTL} = 24h).")
    g_post.add_argument("--loot-dir", default="loot",
                        help="Root directory for enum/modules/bloodhound output (default: loot/).")
    g_post.add_argument("--secretsdump", action="store_true",
                        help="On (Pwn3d!) SMB cred, auto-dump SAM/LSA/NTDS hashes into loot/ and "
                             "append harvested NT hashes to the grow-combo file.")
    g_post.add_argument("--grow-combo",
                        help="Where to append harvested hashes (default: <loot-dir>/auto-grown-creds.txt). "
                             "Use this same file as --combo in the next run to spray the new creds.")

    # ----- Cracking -----
    g_crack = parser.add_argument_group(
        "hash cracking",
        "Offline cracking of NT (SAM/LSA/NTDS) and Kerberos (AS-REP/TGS-REP) hashes. "
        "Cracked plaintexts are auto-appended to the grow-combo file in 'user:password' "
        "form, so the next run can spray them."
    )
    g_crack.add_argument("--crack", action="store_true",
                         help="Auto-crack harvested hashes with hashcat (or john) after --secretsdump "
                              "and after LDAP --asreproast/--kerberoasting.")
    g_crack.add_argument("--wordlist",
                         help="Wordlist path. Default: auto-discover rockyou under /usr/share/wordlists/ etc. "
                              "Falls back to the SecLists location, then ~/wordlists/.")
    g_crack.add_argument("--cracker", choices=["hashcat", "john", "auto"], default="auto",
                         help="Which cracker to use (default: auto = hashcat if present, else john).")
    g_crack.add_argument("--crack-rules",
                         help="Hashcat rules file (e.g. /usr/share/hashcat/rules/best64.rule).")
    g_crack.add_argument("--crack-timeout", type=int, default=CRACK_DEFAULT_TIMEOUT,
                         help=f"Per-attack timeout in seconds (default: {CRACK_DEFAULT_TIMEOUT}).")

    # ----- Export -----
    g_export = parser.add_argument_group("export")
    g_export.add_argument("--export-json",
                          help="Write a structured run summary (valid creds, DCs, hashes, lockout warnings) to this JSON path.")
    g_export.add_argument("--export-csv",
                          help="Write valid credentials in CSV format to this path (one row per finding).")

    # ----- Performance / pacing -----
    g_perf = parser.add_argument_group(
        "performance & pacing",
        "Use --low-power on weak VMs (3 workers, 1 retry, longer timeout, small delay). "
        "Use --delay/--jitter for lockout-safe spraying."
    )
    g_perf.add_argument("--low-power", action="store_true",
                        help="Preset for VMs / weak hosts: workers=3, max-retry=1, timeouts ↑, small delay.")
    g_perf.add_argument("-w", "--workers", type=int,
                        help=f"Parallel threads (default: {DEFAULT_WORKERS}, low-power preset overrides).")
    g_perf.add_argument("--delay", type=float, default=0.0,
                        help="Seconds to sleep between credential attempts (per protocol task).")
    g_perf.add_argument("--jitter", type=float, default=0.0,
                        help="Random extra sleep (0..jitter) added to --delay for anti-lockout.")
    g_perf.add_argument("--netexec-timeout", type=int, default=NETEXEC_TIMEOUT,
                        help=f"Per-attempt nxc --timeout in seconds (default: {NETEXEC_TIMEOUT}).")
    g_perf.add_argument("--subprocess-timeout", type=int, default=SUBPROCESS_TIMEOUT,
                        help=f"Hard Python timeout per nxc invocation (default: {SUBPROCESS_TIMEOUT}).")
    g_perf.add_argument("--max-retry", type=int, default=MAX_RETRY,
                        help=f"Skip a protocol after N consecutive connectivity timeouts (default: {MAX_RETRY}).")
    g_perf.add_argument("--stop-on-success", action="store_true",
                        help="Stop testing credentials on a protocol/host as soon as one valid cred is found "
                             "(avoids lockout and saves time).")

    # ----- Output / logging -----
    g_out = parser.add_argument_group("output & logging")
    g_out.add_argument("-o", "--output",
                       help="Custom nxc --log file path (default: logs/HH-MM-SS-mmm.txt).")
    g_out.add_argument("--cmd-log",
                       help="Path for the shell-quoted commands transcript (default: logs/commands-HH-MM-SS-mmm.log).")
    g_out.add_argument("--no-cmd-log", action="store_true",
                       help="Disable the commands transcript file.")
    g_out.add_argument("-v", "--verbose", action="count", default=0,
                       help="Increase verbosity: -v adds commands + [-] lines, -vv adds raw [*] info.")
    g_out.add_argument("-q", "--quiet", action="store_true",
                       help="Print only valid credentials. Suppresses banner and per-host detail.")
    g_out.add_argument("--strict", action="store_true",
                       help="Exit with code 1 if any real error occurred (subprocess fail, I/O error, "
                            "cracker failure). Useful in CI / scripted pipelines.")
    g_out.add_argument("--no-banner", action="store_true",
                       help="Suppress the decorative startup banner (ASCII art + quote + credits). "
                            "The run summary table is still shown.")

    return parser


def _validate_args(args, parser):
    """Fail-fast checks before we open the cache, spawn subprocesses, or do
    any I/O. Anything user-supplied that's malformed should produce a
    parser.error() (clean exit code 2, no Python traceback)."""
    import os

    def _file_must_exist(flag: str, value: str):
        """Treat the value as a path only if it looks like one (contains '/'
        or '\\' or starts with '~'). Bare names like 'admin' or 'rockyou.txt'
        without a directory part can also be paths — accept those if they
        exist on disk, else assume they were meant as literals."""
        if value is None:
            return
        looks_like_path = (
            os.sep in value or "/" in value or value.startswith("~")
            or value.endswith((".txt", ".lst", ".toml"))
        )
        if not looks_like_path:
            return
        if not Path(value).expanduser().exists():
            parser.error(f"{flag}: file not found: {value!r}")

    # Path-or-literal arguments (the tool accepts both)
    _file_must_exist("-t/--target",   args.target)
    _file_must_exist("-u/--user",     args.user)
    _file_must_exist("-p/--password", args.password)
    _file_must_exist("-H/--hash",     args.nthash)

    # Strictly file-only arguments
    for flag, val in (
        ("--combo",        args.combo),
        ("--wordlist",     args.wordlist),
        ("--crack-rules",  args.crack_rules),
        ("--config",       args.config),
    ):
        if val and not Path(val).expanduser().exists():
            parser.error(f"{flag}: file not found: {val!r}")

    # Numeric ranges (argparse already enforces int/float types)
    range_checks = [
        ("--workers",            args.workers,            1, None),
        ("--delay",              args.delay,              0, None),
        ("--jitter",             args.jitter,             0, None),
        ("--cache-ttl",          args.cache_ttl,          0, None),
        ("--dead-ttl",           args.dead_ttl,           0, None),
        ("--bloodhound-ttl",     args.bloodhound_ttl,     0, None),
        ("--rerun-after",        args.rerun_after,        0, None),
        ("--max-retry",          args.max_retry,          0, None),
        ("--netexec-timeout",    args.netexec_timeout,    1, None),
        ("--subprocess-timeout", args.subprocess_timeout, 1, None),
        ("--crack-timeout",      args.crack_timeout,      1, None),
        ("--resolve-timeout",    args.resolve_timeout,    0.1, None),
    ]
    for flag, value, lo, hi in range_checks:
        if value is None:
            continue
        if value < lo or (hi is not None and value > hi):
            bound = f">= {lo}" + (f" and <= {hi}" if hi is not None else "")
            parser.error(f"{flag}: must be {bound} (got {value})")

    # Mutual exclusion + 'you must provide one' — caught later by
    # NxcAutomator._build_credentials but message there is better when we
    # state it explicitly here.
    if args.combo and (args.user or args.password or args.nthash):
        parser.error("--combo cannot be combined with -u/-p/-H "
                     "(combo lines carry the user already).")

    # --exam-safe: refuse at startup if any requested module is an automated
    # exploitation module. Matched case-insensitively, '-'/'_' interchangeable.
    if args.exam_safe and args.modules:
        blocked = {_normalize_module(b) for b in EXAM_SAFE_BLOCKLIST}
        offenders = [
            m.strip() for m in args.modules.split(",")
            if m.strip() and _normalize_module(m) in blocked
        ]
        if offenders:
            parser.error(
                "--exam-safe: refusing to run prohibited module(s): "
                f"{', '.join(offenders)}. These perform automated exploitation "
                "and are blocked in exam-safe mode. Drop them from --modules to proceed."
            )

    # --cracker choice already validated by argparse choices=

    # Sanity: cache-path's parent must exist (or be creatable)
    if args.cache_path:
        cp = Path(args.cache_path).expanduser()
        if cp.exists() and not cp.is_file():
            parser.error(f"--cache-path: not a regular file: {cp}")

    # If --update-nxc or --clear-tried-cache were the user's intent they
    # should have been handled earlier; reaching here means -t is required.
    # (This is enforced separately in main() after _validate_args.)


def _apply_low_power_defaults(args):
    """Resolve --low-power into concrete values. Explicit user flags win."""
    if not args.low_power:
        return args
    if args.workers is None:
        args.workers = LOW_POWER_PROFILE["workers"]
    if args.max_retry == MAX_RETRY:
        args.max_retry = LOW_POWER_PROFILE["max_retry"]
    if args.netexec_timeout == NETEXEC_TIMEOUT:
        args.netexec_timeout = LOW_POWER_PROFILE["netexec_timeout"]
    if args.subprocess_timeout == SUBPROCESS_TIMEOUT:
        args.subprocess_timeout = LOW_POWER_PROFILE["subprocess_timeout"]
    if args.delay == 0.0:
        args.delay = LOW_POWER_PROFILE["delay"]
    return args


def _merge_toml_into_args(args, parser):
    """Overlay TOML values onto argparse defaults — CLI flags still win because
    we only override values left at their argparse default."""
    if not args.config:
        return args
    if not Path(args.config).expanduser().exists():
        parser.error(f"--config: file not found: {args.config!r}")
    try:
        cfg = _load_toml_config(args.config)
    except Exception as exc:
        parser.error(f"--config: failed to parse {args.config!r}: {exc}")
    defaults = parser.parse_args([])  # what argparse would set with no CLI flags
    for key, value in cfg.items():
        key_attr = key.replace("-", "_")
        if not hasattr(args, key_attr):
            print(f"{YELLOW}⚠ --config: unknown key {key!r} (ignored){RESET}", file=sys.stderr)
            continue
        if getattr(args, key_attr) == getattr(defaults, key_attr, None):
            setattr(args, key_attr, value)
    return args


def _find_update_nxc_script() -> Path | None:
    """Locate scripts/update-nxc.sh whether running from a checked-out repo
    OR from a pipx/pip install (where the script is bundled as package data
    under netexec_automator/_scripts/)."""
    here = Path(__file__).resolve().parent
    candidates = [
        here.parent / "scripts" / "update-nxc.sh",      # repo layout
        here / "_scripts" / "update-nxc.sh",             # pipx/pip install (package_data)
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def main():
    parser = _build_parser()
    args = parser.parse_args()

    if args.update_nxc:
        script = _find_update_nxc_script()
        if not script:
            print(
                f"{RED}Error: update-nxc.sh not found in any of the expected locations.{RESET}\n"
                f"  {DIM}Run the script directly from the repo: ./scripts/update-nxc.sh{RESET}\n"
                f"  {DIM}or: curl -fsSL https://raw.githubusercontent.com/Givaa/netexec-automator/main/scripts/update-nxc.sh | bash{RESET}",
                file=sys.stderr,
            )
            sys.exit(2)
        sys.exit(subprocess.call(["bash", str(script)]))

    if args.clear_tried_cache:
        # One-shot maintenance: wipe the tried_creds table and exit. Honors
        # --cache-path so concurrent CI runs can clear their own DB.
        from .cache import HostCache
        cache_path = Path(args.cache_path).expanduser() if args.cache_path else CACHE_DEFAULT_PATH
        if not cache_path.exists():
            print(f"{DIM}cache file does not exist at {cache_path} — nothing to clear{RESET}")
            sys.exit(0)
        cache = HostCache(cache_path, ttl=args.cache_ttl)
        try:
            n = cache.clear_tried_cache()
        finally:
            cache.close()
        print(f"cleared {n} tried_creds entries from {cache_path}")
        sys.exit(0)

    if not args.target:
        parser.error("-t/--target is required (or use --update-nxc to install the nxc binary).")

    args = _merge_toml_into_args(args, parser)
    args = _apply_low_power_defaults(args)
    _validate_args(args, parser)
    if args.workers is None:
        args.workers = DEFAULT_WORKERS
    # nmap pre-scan is on by default now (learn open ports per host, cache them).
    nmap_enabled = _nmap_enabled(args)
    if args.quiet:
        verbosity = V_QUIET
    else:
        verbosity = min(args.verbose, V_DEBUG)
    try:
        runner = NxcAutomator(
            target=args.target,
            user=args.user,
            password=args.password,
            nthash=args.nthash,
            combo=args.combo,
            domain=args.domain,
            kerberos=args.kerberos,
            null_session=args.null_session,
            output=args.output,
            workers=args.workers,
            mode=args.mode,
            nmap_enabled=nmap_enabled,
            cache_enabled=not args.no_cache,
            cache_ttl=args.cache_ttl,
            dead_ttl=args.dead_ttl,
            cache_path=args.cache_path,
            scan_only=args.scan_only,
            rescan=args.rescan,
            verbosity=verbosity,
            enum_enabled=args.enum,
            modules=args.modules,
            bloodhound_enabled=args.bloodhound,
            bloodhound_force=args.bloodhound_force,
            bloodhound_ttl=args.bloodhound_ttl,
            loot_dir=args.loot_dir,
            cmd_log=args.cmd_log,
            cmd_log_disabled=args.no_cmd_log,
            delay=args.delay,
            jitter=args.jitter,
            netexec_timeout=args.netexec_timeout,
            subprocess_timeout=args.subprocess_timeout,
            max_retry=args.max_retry,
            stop_on_success=args.stop_on_success,
            only_protocols=args.only,
            exclude_protocols=args.exclude,
            secretsdump=args.secretsdump,
            grow_combo=args.grow_combo,
            export_json=args.export_json,
            export_csv=args.export_csv,
            crack_enabled=args.crack,
            wordlist=args.wordlist,
            cracker=args.cracker,
            crack_rules=args.crack_rules,
            crack_timeout=args.crack_timeout,
            strict=args.strict,
            resolve_enabled=not args.no_resolve,
            resolve_timeout=args.resolve_timeout,
            no_banner=args.no_banner,
            skip_tried=args.skip_tried,
            rerun_after=args.rerun_after,
            reachability_check=not args.no_reachability_check,
        )
        runner.run()
    except ValueError as exc:
        print(f"{RED}{BOLD}Error:{RESET} {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
