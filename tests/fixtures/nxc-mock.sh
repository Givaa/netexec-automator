#!/usr/bin/env bash
# nxc-mock.sh — fake `nxc` binary for end-to-end tests.
#
# Drives the tool's exit-code + output handling without needing a real
# NetExec install or a real AD. The behaviour is controlled by env vars:
#
#   NXA_MOCK_TARGET=<ip>         target this mock should "pwn" (default: 10.10.10.5)
#   NXA_MOCK_USER=<user>         valid user (default: administrator)
#   NXA_MOCK_PASS=<password>     valid password (default: Summer2025!)
#   NXA_MOCK_PWN3D=1             append '(Pwn3d!)' to the [+] line (default: yes)
#   NXA_MOCK_FAIL=1              return exit 1 (subprocess error)
#   NXA_MOCK_TIMEOUT_SECS=<n>    sleep N seconds before responding (simulates timeout)
#
# This script is intentionally minimal — just enough to exercise the
# tool's classification / harvest / crack pipeline.

set -u

# Defaults
MOCK_TARGET="${NXA_MOCK_TARGET:-10.10.10.5}"
MOCK_USER="${NXA_MOCK_USER:-administrator}"
MOCK_PASS="${NXA_MOCK_PASS:-Summer2025!}"
MOCK_PWN3D="${NXA_MOCK_PWN3D:-1}"
MOCK_FAIL="${NXA_MOCK_FAIL:-0}"

# Parse the bits of the nxc CLI we care about
proto="${1:-smb}"
shift || true
target="${1:-}"
shift || true

user=""
secret=""
local_auth=0
mode_args=()
while [ $# -gt 0 ]; do
    case "$1" in
        -u) user="$2"; shift 2 ;;
        -p) secret="$2"; shift 2 ;;
        -H) secret="$2"; shift 2 ;;
        --local-auth) local_auth=1; shift ;;
        --shares|--users|--sessions|--loggedon-users|--pass-pol|--sam|--lsa|--ntds|--asreproast|--kerberoasting)
            mode_args+=("$1"); shift
            # asrep/kerb take an output-file arg
            if [ "${1:-}" ] && [[ "${1:-}" != -* ]]; then
                mode_args+=("$1"); shift
            fi
            ;;
        --version)
            echo "NetExec Version : 1.5.0 (mocked)"; exit 0 ;;
        *) shift ;;
    esac
done

if [ -n "${NXA_MOCK_TIMEOUT_SECS:-}" ]; then
    sleep "$NXA_MOCK_TIMEOUT_SECS"
fi

if [ "$MOCK_FAIL" = "1" ]; then
    echo "[!] mock-induced failure" >&2
    exit 1
fi

# Only the configured (target, user, pass) combination "succeeds".
authed=0
if [ "$target" = "$MOCK_TARGET" ] && [ "$user" = "$MOCK_USER" ] && [ "$secret" = "$MOCK_PASS" ]; then
    authed=1
fi

if [ "$proto" = "smb" ]; then
    echo "SMB         $target      445    HOST             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)"
    if [ "$authed" = "1" ]; then
        suffix=""
        [ "$MOCK_PWN3D" = "1" ] && suffix=" (Pwn3d!)"
        echo "SMB         $target      445    HOST             [+] corp.local\\${user}:${secret}${suffix}"
        # Mode-specific extra output
        for arg in "${mode_args[@]+"${mode_args[@]}"}"; do
            case "$arg" in
                --shares)
                    echo "SMB         $target      445    HOST             [*] Enumerated shares"
                    echo "SMB         $target      445    HOST             Share           Permissions     Remark"
                    echo "SMB         $target      445    HOST             ADMIN\$          READ,WRITE      Remote Admin"
                    echo "SMB         $target      445    HOST             C\$              READ,WRITE      Default share"
                    ;;
                --pass-pol)
                    echo "SMB         $target      445    HOST             [+] Dumping password info"
                    echo "SMB         $target      445    HOST             Minimum password length: 7"
                    echo "SMB         $target      445    HOST             Account Lockout Threshold: 3"
                    echo "SMB         $target      445    HOST             Account Lockout Duration: 30 minutes"
                    ;;
                --sam)
                    echo "SMB         $target      445    HOST             [+] Dumping SAM hashes"
                    echo "SMB         $target      445    HOST             Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::"
                    echo "SMB         $target      445    HOST             Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
                    ;;
                --ntds)
                    echo "SMB         $target      445    HOST             [+] Dumping NTDS"
                    echo "SMB         $target      445    HOST             corp.local\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
                    ;;
            esac
        done
    else
        echo "SMB         $target      445    HOST             [-] corp.local\\${user}:${secret} STATUS_LOGON_FAILURE"
    fi
elif [ "$proto" = "ldap" ]; then
    if [ "$authed" = "1" ]; then
        echo "LDAP        $target      389    HOST             [+] corp.local\\${user}:${secret}"
        for arg in "${mode_args[@]+"${mode_args[@]}"}"; do
            case "$arg" in
                --users)
                    echo "LDAP        $target      389    HOST             [+] Enumerated users"
                    echo "LDAP        $target      389    HOST             samaccountname: administrator"
                    ;;
                --asreproast)
                    # Find the output file path in mode_args
                    for ((i=0; i<${#mode_args[@]}; i++)); do
                        if [ "${mode_args[i]}" = "--asreproast" ] && [ -n "${mode_args[$((i+1))]:-}" ]; then
                            echo '$krb5asrep$23$alice@CORP.LOCAL:c5d2b3e4f6a7b8c9d0e1f2a3b4c5d6e7$f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9' > "${mode_args[$((i+1))]}"
                            break
                        fi
                    done
                    ;;
            esac
        done
    else
        echo "LDAP        $target      389    HOST             [-] corp.local\\${user}:${secret} STATUS_LOGON_FAILURE"
    fi
else
    # Other protocols: just unauth or auth, no extras
    if [ "$authed" = "1" ]; then
        echo "${proto^^}    $target      ?    HOST             [+] ${user}:${secret}"
    else
        echo "${proto^^}    $target      ?    HOST             [-] ${user}:${secret}"
    fi
fi

exit 0
