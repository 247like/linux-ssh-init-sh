#!/bin/sh
# =========================================================
# linux-ssh-init-sh
# Server Init & SSH Hardening Script
#
# Author:  247like
# GitHub:  https://github.com/247like/linux-ssh-init-sh
# License: MIT
#
# Release: v4.7.8 (Enterprise Hardening — 18th-round red-team / scenario fixes)
#
# POSIX sh compatible (Debian dash / CentOS / Alpine / Ubuntu / RHEL)
#
# Changelog v4.7.8 (post-v4.7.7 18th-round red-team + scenario walk-through):
#   - [HIGH] PATH inheritance hardening: previously, $PATH was inherited
#            unsanitized from the caller. In CI / sudo-with-env_keep+=PATH
#            scenarios an attacker controlling the calling shell's env could
#            plant fake passwd/useradd/stat/whoami/etc binaries that the
#            script then executes as root. Now sets a fixed PATH at the top.
#   - [HIGH] restart_sshd refuses early when in a chroot. v4.7.7 only blocked
#            the direct-spawn fallback; the systemctl path could still cross
#            the chroot boundary via /run/dbus and restart the HOST's sshd
#            with the CHROOT's modified config. Now bails at the function
#            entry via in_chroot_or_unknown.
#   - [MED W1-1] update_system: SYSTEM_UPDATE_START + SYSTEM_UPDATE_DONE
#            audit_log entries (apt/dnf/yum/apk upgrade is a major mutation).
#   - [MED W2-2] FIREWALL_OPENED audit only fires when rule was ACTUALLY
#            installed; pre-existing rules emit FIREWALL_NOOP. Stops every
#            idempotent re-run from polluting the audit log.
#   - [MED W6-1] KEY_FETCH_FAILED audit entry after 3 retries exhausted
#            (forensic breadcrumb for why STRICT mode aborted).
#   - [MED W8-1] STRANDED_MUTATIONS_DETECTED audit when --yes + non-empty
#            prev-run artifact mirror. Cron-driven runs no longer silently
#            accumulate detected-but-unreconciled mutations.
#   - [LOW]  --key-gh=USERNAME value redacted in START audit entry (parity
#            with --key-url and --key-raw).
#   - [doc]  README "公钥失败" / "Key Failure" table row clarified: managed
#            block writes PasswordAuthentication=yes (preserves existing
#            password-login path) AND new user is kept locked.
#   - [doc]  README audit-log enumeration completed — all 37+ ACTION names
#            now listed, with high-priority alert candidates bold-marked
#            (ROLLBACK_RM_FAILED / STRANDED_MUTATIONS_DETECTED / etc).
#   - [doc]  README "Files modified" table now lists script.lock and
#            last-artifacts-UID paths (v4.7.6 additions previously omitted).
#
# Changelog v4.7.7 (post-v4.7.6 16th-round perf/FS/container/exotic-shell audit):
#   - [HIGH] Direct-spawn sshd fallback now refuses ALSO when in a chroot
#            without separate PID namespace (e.g. operator did
#            `chroot /mnt/target` from host console). Previously, only the
#            SSH-into-host scenario was guarded; chroot-from-console would
#            let `pkill -x sshd` reach the HOST's sshd and drop every SSH
#            session on the machine. New in_chroot_or_unknown helper does
#            this via /proc/1/root inode comparison.
#   - [MED]  Script-level mutex liveness check now uses both /proc/$pid AND
#            kill -0 as a fallback, and REFUSES when the holder's status is
#            ambiguous (chroot without /proc, etc) rather than reclaiming
#            and letting two concurrent runs race-corrupt sshd_config.
#   - [MED]  setup_rollback's snapshot cp now fails LOUDLY on ENOSPC / NFS
#            errors AND verifies non-empty result. Previously a silent cp
#            failure left an empty snapshot — and the eventual rollback would
#            cp that empty snapshot OVER /etc/ssh/sshd_config, bricking the
#            box. Refuses to proceed without a valid snapshot.
#   - [MED]  backup_config_persistent's snapshot cp same hardening; on
#            failure removes the partial file (restore.sh would otherwise
#            install a 0-byte sshd_config) and warns.
#   - [MED]  record_last_applied now writes atomically via tmp+mv. Previous
#            direct truncate-then-write left partial state on signal/ENOSPC.
#   - [LOW]  audit_log falls back to stderr (`AUDIT-FALLBACK ...`) when
#            /var/log is unwritable. The ROLLBACK record is the most
#            important forensic event; losing it silently would leave the
#            operator with no idea why rollback fired.
#   - [INFO] README adds a logrotate(8) snippet for /var/log/server-init*.log
#            (zh+en). Operators of high-frequency installs (CI / fleet) need
#            a hint that there's no built-in rotation.
#   - [CLEAN] Exotic shells (yash, ksh93, mksh, posh, OpenBSD pdksh) and old
#            tool versions verified: no new portability issues found.
#
# Changelog v4.7.6 (post-v4.7.5 13th-round adversarial audit):
#   - [CRIT] handle_selinux now initializes __selinux_done="n" at function
#            entry. Previously, the "all 3 semanage attempts failed" path
#            left it unset; under `set -u` the subsequent test crashed the
#            script and triggered a full rollback — defeating the non-strict
#            graceful-degrade design.
#   - [HIGH N1] Script-level mutex at $RUNTIME_DIR/script.lock prevents
#            concurrent invocations from interleave-corrupting sshd_config.
#            Stale-PID detection allows recovery from crashed prior runs.
#   - [HIGH N2] artifact_track now ALSO mirrors to $RUNTIME_DIR/last-artifacts-UID
#            (RUNTIME_DIR survives across script invocations; TMP_DIR doesn't).
#            On SIGKILL/OOM/power-loss, the next script run surfaces the
#            stranded artifacts so the operator knows to manually clean.
#   - [HIGH N3] audit_log strips newlines from $action and $details. Without
#            this, a $details derived from a tampered /etc/passwd field 6
#            could inject forged "ACTION: FAKE" entries into the audit log.
#   - [MED] validate_port rejects leading-zero ports. `--port=03306` used to
#            decimal-pass to 3306, bypass is_hard_reserved's string-only
#            case match, and write `Port 03306` to sshd_config — silently
#            shadowing MySQL on that port. Same vector for `--port=0022`
#            that script-treated as non-standard while sshd parsed as 22,
#            racing firewall/SELinux state vs the daemon's reality.
#   - [MED N5] Rollback rm-failure now audit-logged (ROLLBACK_RM_FAILED) and
#            sets rollback_clean=0. Read-only /etc previously left stale
#            sudoers entries after user deletion — a privilege primitive
#            for any future re-created user with the same name.
#   - [MED N6] MOTD_BAK-missing during rollback now surfaces as ROLLBACK_
#            MOTD_BAK_MISSING audit + non-clean rollback (was silent).
#   - [MED] Strip block for SELINUX_* lines: previous `grep -v ... && mv ||
#            rm` broke when grep matched zero lines (file was all SELINUX_*).
#            Now uses `|| true` after grep so mv always runs.
#   - [MED] Duplicate `--user=` / `--port=` / `--key-*` now hard-fails instead
#            of silently last-wins. Empty `--port=` and `--key-X=` values
#            are also rejected (previously caused interactive-prompt EOF →
#            silent port-22 downgrade).
#   - [LOW] validate_username + --key-gh now reject embedded newlines BEFORE
#            grep (POSIX grep is per-line-anchored — multi-line values
#            silently bypassed). Closes the log-disclosure / future-refactor
#            footgun.
#   - [LOW] public_ip from ipify is sanitized to digits/dots only (≤15 char).
#            Prevents a MITM'd response from injecting ANSI CSI sequences
#            into the operator's terminal scrollback via the summary box.
#
# Changelog v4.7.5 (post-v4.7.4 11th-round audit):
#   - [MED] SELinux NOOP-vs-ADD provenance: v4.7.4 tracked NOOP labels the
#           same as ADDED labels, which let rollback and stale-cleanup
#           `semanage port -d` labels we never installed (sysadmin-set or
#           cross-tool-set). NOOP path no longer artifact_tracks; persisted
#           state gains `SELINUX_OWNED=y/n` so stale-cleanup only deletes
#           OWNED labels and emits STALE_SELINUX_KEPT for the rest.
#   - [MED] Stale SELinux residue across mid-state crash: after a successful
#           cross-run `semanage port -d`, the SELINUX_PORT= and SELINUX_OWNED=
#           lines are STRIPPED from LAST_APPLIED_FILE immediately (not just
#           overwritten by the post-handle_selinux record_last_applied call).
#           Eliminates the brief window where the file claimed ownership of a
#           label that had just been deleted.
#   - [MED] CI: test-distros now asserts the v4.7.4 audit entries
#           (USER_CREATED / PASSWORD_CLEARED / KEYS_DEPLOYED /
#           MANAGED_BLOCK_INSTALLED) actually fire on the happy path.
#   - [MED] CI: new test-restore-checksum-gate job verifies restore.sh
#           refuses missing checksums.sha256 AND that FORCE=1 bypasses.
#   - [LOW] Forensic gap: `INSECURE_KEY_URL` audit entry fires when a
#           plaintext http:// key URL is fetched in non-strict mode.
#   - [LOW] STALE_SELINUX_KEPT / STALE_SELINUX_REMOVE_FAILED /
#           STALE_SELINUX_SKIP audit entries for full state coverage.
#   - [INFO] Both READMEs now document the audit-log action names (for SIEM
#            integration) and the v4.7.5 SELinux ownership semantics.
#
# Changelog v4.7.4 (post-v4.7.3 9th-round audit):
#   - [LOW]  --key-raw \c/\0 check now uses raw printf+exit (the previous
#            `die` call was unreachable: die() is defined AFTER the argv loop,
#            so an undefined-function "command not found" would silently
#            proceed, bypassing the defense-in-depth check).
#   - [MED]  SELinux port label leak across runs: LAST_APPLIED_FILE now
#            records SELINUX_PORT=N; remove_stale_firewall_port also calls
#            `semanage port -d` on the OLD port. No more cruft accumulation.
#   - [MED]  Idempotent same-port SELinux re-run: handle_selinux now
#            pre-checks `semanage port -l` and emits SELINUX_PORT_NOOP
#            instead of the misleading "previous SELinux type was
#            overwritten" warning.
#   - [MED]  Forensic audit gap: USER_CREATED, PASSWORD_CLEARED, KEYS_DEPLOYED
#            now in the audit trail (previously only artifact_track + info).
#   - [MED]  README documents `FORCE=1 sh restore.sh` for the case where
#            checksums.sha256 was lost and operator must bypass verification.
#   - [LOW]  Symlink-defense hardening: 5 sites now call unlink_if_symlink
#            before write (init_log_files / record_last_applied / sudoers /
#            systemd override / motd banner). BBR sysctl path refuses to
#            append when /etc/sysctl.conf is a symlink. All require prior
#            root-equiv compromise to weaponize but tightens defense.
#
# Changelog v4.7.3 (post-v4.7.2 fresh-eyes audit):
#   - [HIGH H2] finalize_user_password_policy now surfaces double-failure
#               (passwd -d AND usermod -U both failing) via ACCOUNT_LOCKED_REASON
#               + audit_log instead of silently leaving account broken.
#   - [HIGH H3] deploy_keys defensively rejects home directories that are
#               not owned by the target user (defends against tampered
#               /etc/passwd → privilege-escalation primitive).
#   - [HIGH H4] cleanup_sshd_config_d will not overwrite a pre-existing
#               .bak_server_init from a prior crashed run — uses timestamped
#               name instead.
#   - [HIGH H5] Persist last-applied port/backend in /var/lib/server-init/last-applied;
#               on next run with different --port, clean the stale firewall
#               rule (no more "every prior port stays open").
#   - [HIGH H6] setup_rollback skips .bak_server_init files when snapshotting
#               so stage-3 rollback restore cannot reintroduce stale data.
#   - [HIGH H7] SELinux `semanage port -m` path audit-logs the overwrite +
#               warns loudly; STRICT mode refuses to silently overwrite.
#   - [HIGH H8/H9] CI: existing-user-safe now asserts `passwd -S` reports P;
#               cross-user comment corrected.
#   - [INFO C1]  enhanced_ssh_test ssh-client login test is INHERENTLY
#               inconclusive (root has no client privkey) — kept warn+return-0
#               behavior but added LOGIN_TEST_PASSED / LOGIN_TEST_INCONCLUSIVE
#               audit_log entries.
#   - [MED] --key-raw rejects literal \\c and \\0 escapes (printf %b truncation
#           hazard); interactive raw paste uses real newline (no %b at all).
#   - [MED] cleanup_old_backups grep -c fix — empty backup_list no longer
#           produces "0\\n0" that broke numeric -gt compare.
#   - [MED] ensure_port_tools tries multiple nc package names (netcat-openbsd,
#           ncat, nmap-ncat, netcat) for cross-distro coverage.
#   - [MED] restore.sh REFUSES when checksums.sha256 is missing or sha256sum
#           unavailable; set FORCE=1 to override.
#   - [MED] fetch_keys via wget uses --quota=$KEY_MAX_BYTES (wget has no
#           --max-filesize) to bound on-disk damage.
#   - [MED] sanitize_sshd_config stops at first `Match` line — operator's
#           Match-block-scoped directives are no longer silently commented out.
#   - [MED] update_motd grep anchored to start-of-line; operator's MOTD lines
#           containing "Login User:" etc. are no longer accidentally stripped.
#   - [MED] print_final_summary suppresses ssh command when ACCOUNT_LOCKED.
#   - [MED] --delay-restart explicitly tells the operator about the
#           systemd override.conf that will apply on next manual restart.
#   - [MED] restart_sshd direct-spawn fallback REFUSES when SSH_CONNECTION
#           is set (would kill operator's own session in a chroot/container).
#   - [MED] audit_log added for BBR_ENABLED, FIREWALL_OPENED, SUDOERS_WRITTEN,
#           DROPIN_RENAMED, MANAGED_BLOCK_INSTALLED, SYSTEMD_OVERRIDE_WRITTEN,
#           MOTD_BANNER_WRITTEN, SELINUX_PORT_ADDED/MODIFIED/FAIL.
#   - [LOW] STALE_FIREWALL_REMOVED audit entry on port-change cleanup.
#   - [LOW] DIRECT_SPAWN / DIRECT_SPAWN_REFUSED audit entries.
#
# Changelog v4.7.2 (post-v4.7.1 audit fixes):
#   - [HIGH] safe_configure_sudo: validate + write the NEW stable file BEFORE
#            touching any legacy files (prevents lockout-of-admin when visudo
#            fails on the new template).
#   - [HIGH] Legacy-sudoers cleanup glob now requires digits-only suffix,
#            preventing cross-user deletion (running script for "admin" no
#            longer deletes "server-init-admin-bot"). Operator-managed files
#            like "server-init-<user>-special-policy" are preserved.
#   - [MED]  rollback_handler skips restart_sshd when restored sshd_config
#            fails `sshd -t` — pushing a broken config to the live daemon
#            could crash sshd and leave the machine unreachable.
#   - [MED]  finalize_user_password_policy: keep new account LOCKED when
#            sudo deployment also failed (avoid passwordless+no-sudo combo).
#   - [LOW]  CI test-existing-user-safe comment corrected (sudoers is NEVER
#            written for pre-existing accounts — that's by design).
#   - [LOW]  CI: new test-cross-user-sudoers-safe job (regression test for
#            the HIGH glob bug).
#   - [LOW]  CI: new test-legacy-sudoers-cleanup job (verifies v4.6.x
#            timestamped files are removed AND audit-logged).
#
# Changelog v4.7.1 (post-v4.7.0 audit fixes):
#   - [CRIT R1] passwd -d regression: only clear password for NEW accounts;
#               pre-existing admin passwords are preserved
#   - [CRIT R2] rollback now RENAMES .bak_server_init back instead of deleting
#               (prevents permanent loss of original drop-in content)
#   - [CRIT R3] update_motd modifications tracked via MOTD_BAK artifact;
#               rollback restores from .bak
#   - [CRIT R4] restart_sshd grew a direct-spawn fallback (pkill+sshd) for
#               minimal/no-init environments; CI live-restart job now passes
#   - [HIGH H1] safe_configure_sudo failure is no longer silent (audit_log +
#               STRICT abort)
#   - [HIGH H2] FIREWALL_PORT artifact tagged with backend (ufw/firewalld/
#               iptables) — rollback only undoes that backend
#   - [HIGH H3] sshd -T fallback warns loudly + STRICT mode refuses approximate
#               grep-based validation
#   - [HIGH H4] Rollback path forces sshd restart even under --delay-restart
#   - [HIGH H6] safe_configure_sudo cleans up pre-v4.7.0 timestamped sudoers
#               variants (one stable file per user)
#   - [MED M1]  Stdout AUTO_SKIP message redacts --key-raw / --key-url values
#   - [MED M2]  --key-gh validates GitHub-username regex before URL substitution
#   - [MED M3]  fetch_keys downloads via temp file (max-filesize errors no
#               longer masked by SIGPIPE → curl exit 0)
#   - [MED M4]  rollback while-read tolerates torn last-line writes (no LF)
#   - [MED M5]  pkill -KILL -u $user before userdel in rollback
#   - [MED M6]  iptables-restore explicit warning about wiping other rules
#   - [MED M8]  ipify probe uses --proto '=https' --max-redirs 2
#   - [LOW]     --version / --help clean up TMP_DIR before exit
#   - [LOW]     dropped GNU-only `xargs -r` (BusyBox compat)
#
# Changelog v4.7.0 (Enterprise Hardening):
#   - [CRIT] Defer `passwd -d` until key deployment confirmed (avoids passwordless+password-auth window)
#   - [CRIT] Rollback now tracks all created artifacts (sudoers, systemd override, motd, BBR, user)
#   - [CRIT] Rollback restores iptables.backup + re-validates sshd -t + listening port
#   - [CRIT] Clean `.bak_server_init` drop-ins on rollback
#   - [CRIT] All color output via printf '%b' (fixes dash literal-escape output)
#   - [CRIT] `--key-raw=` argv: apply printf %b for literal \n support
#   - [HIGH] restore.sh now verifies checksums.sha256 before applying
#   - [HIGH] Backup dir umask 077 + explicit chmod 700 (no more world-readable history)
#   - [HIGH] /tmp backup-dir fallback hardened (refuses pre-existing dir with wrong owner)
#   - [HIGH] fetch_keys: --max-filesize, --max-redirs, strict mode requires https
#   - [HIGH] validate_ssh_config uses sshd -T (Match-block aware) instead of grep|tail
#   - [HIGH] safe_configure_sudo checks wheel/sudo group membership
#   - [HIGH] Trap handler blocks re-entrant signals + explicit INT/TERM handlers
#   - [HIGH] update_motd preserves a real backup (.bak retained for one cycle)
#   - [MED] Stable sudoers.d filename per user (no more orphan files on re-run)
#   - [MED] Port lock cleanup on success
#   - [MED] `protect_sshd_service` runs even with --delay-restart
#   - [MED] chown verification post-deploy_keys (catches NFS root_squash silent failures)
#   - [MED] install_managed_block: mv guarded with die
#   - [MED] remove_managed_block tolerant of CRLF/whitespace markers
#   - [MED] Replace `echo "$user_input" | ...` with printf '%s\n' (bash/dash echo divergence)
#   - [MED] Health report uses if/then/else (no &&...|| precedence trap)
#   - [LOW] iptables.backup / backup.info / checksums.sha256 explicit chmod 600
#   - [LOW] LC_ALL=C exported (deterministic sort/awk regex)
#   - [LOW] Optional external IP lookup gated by --no-ip-probe
# =========================================================

set -u
# [v4.7.0] Deterministic locale for sort/awk/sed/grep semantics
LC_ALL=C
LANGUAGE=C
export LC_ALL LANGUAGE

# [v4.7.8 FIX-HIGH] PATH hardening. The script invokes ~245 binaries; many
# without `command -v` guards. If PATH is attacker-controlled (e.g. CI runner
# env, sudo with env_keep+=PATH, a poisoned .bashrc sourced before sudo), an
# attacker can plant fake `passwd`/`useradd`/`stat`/`whoami`/etc in $PATH
# and the script will run them as root. Reset PATH to a known-safe default
# BEFORE any external command runs. /usr/local/* first so legitimate local
# installs (e.g. AlmaLinux's curl) still work. PATH=. is NEVER included.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

print_usage() {
  cat <<EOF
linux-ssh-init-sh v4.7.8 — Server Init & SSH Hardening

USAGE:
  ./init.sh [OPTIONS]

CONTROL:
  --lang=zh|en          Force locale (default: zh)
  --yes                 Skip the final "proceed?" prompt
  --strict              Abort on any critical failure (no fallback)
  --delay-restart       Write config but do not restart sshd / run tests
  --no-ip-probe         Skip public IP lookup (offline-friendly)
  -V, --version         Print version and exit
  -h, --help            This help

USER & PORT:
  --user=NAME           Login user (default: deploy; "root" allowed)
  --port=22|random|N    SSH port (random uses 49152-65535)

KEY SOURCE (pick one):
  --key-gh=USERNAME     Pull from https://github.com/USERNAME.keys
  --key-url=URL         Fetch from URL (https://; http:// only outside strict)
  --key-raw="ssh-..."   Inline key(s); use literal \\n between multiple lines

SYSTEM:
  --update / --no-update    Upgrade installed packages
  --bbr    / --no-bbr       Enable TCP BBR congestion control

LOGS:
  /var/log/server-init.log         (debug log)
  /var/log/server-init-audit.log   (audit trail)
  /var/log/server-init-health.log  (post-run snapshot)
  /var/backups/ssh-config/<TS>/    (restore.sh per-run)
EOF
}

# --help / --version should not require root and should not acquire locks.
for __early_arg in "$@"; do
  case "$__early_arg" in
    --version|-V)
      echo "linux-ssh-init-sh v4.7.8 Enterprise Hardening"
      exit 0 ;;
    --help|-h)
      print_usage
      exit 0 ;;
  esac
done
unset __early_arg

if [ "$(id -u)" -ne 0 ]; then
  __early_lang="zh"
  for __early_arg in "$@"; do
    case "$__early_arg" in
      --lang=en) __early_lang="en" ;;
      --lang=zh) __early_lang="zh" ;;
    esac
  done
  if [ "$__early_lang" = "en" ]; then
    echo "Must be run as root"
  else
    echo "必须以 root 权限运行此脚本"
  fi
  exit 1
fi
unset __early_lang __early_arg

SCRIPT_START_TIME=$(date +%s)

# ---------------- Configuration ----------------
LANG_CUR="zh"
LOG_FILE="/var/log/server-init.log"
AUDIT_FILE="/var/log/server-init-audit.log"
BACKUP_REPO="/var/backups/ssh-config"
SSH_CONF="/etc/ssh/sshd_config"
SSH_CONF_D="/etc/ssh/sshd_config.d"
DEFAULT_USER="deploy"
BLOCK_BEGIN="# BEGIN SERVER-INIT MANAGED BLOCK"
BLOCK_END="# END SERVER-INIT MANAGED BLOCK"
# [v4.7.3 FIX-H5] Persist the last-applied SSH port across script runs so
# that on the next run with a DIFFERENT port we can clean the firewall rule
# we previously installed. The file lives under /var/lib/server-init (root-
# only, persists across reboots).
LAST_APPLIED_FILE="/var/lib/server-init/last-applied"

# ---------------- [SEC] Atomic Secure Temp Directory ----------------
old_umask=$(umask)
umask 077
TMP_DIR=""
if command -v mktemp >/dev/null 2>&1; then
  TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t ssh-init-XXXXXX 2>/dev/null || echo "")
fi
if [ -z "$TMP_DIR" ]; then
  rand_suffix=""
  if [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then
    rand_suffix=$(od -An -N4 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
  fi
  [ -z "$rand_suffix" ] && rand_suffix="$$"
  TMP_DIR="/tmp/ssh-init.${$}.${rand_suffix}.$(date +%s 2>/dev/null || echo 0)"
  # [SEC-FIX] Use mkdir without -p to avoid reusing existing directories
  mkdir "$TMP_DIR" 2>/dev/null || {
    # Retry with different name
    TMP_DIR="/tmp/ssh-init.${rand_suffix}.$$"
    mkdir "$TMP_DIR" 2>/dev/null || { echo "FATAL: Cannot create temp directory: $TMP_DIR" >&2; exit 1; }
  }
fi
chmod 700 "$TMP_DIR" 2>/dev/null || true
umask "$old_umask"

# ---------------- [SEC] State & Lock Management ----------------
RUNTIME_DIR=""
for try_dir in "/run/server-init" "/var/lib/server-init"; do
  if mkdir -p "$try_dir" 2>/dev/null; then
    RUNTIME_DIR="$try_dir"
    break
  fi
done

if [ -z "$RUNTIME_DIR" ]; then
  rand_rt=""
  if [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then
    rand_rt=$(od -An -N4 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
  fi
  [ -z "$rand_rt" ] && rand_rt="$$"
  RUNTIME_DIR="/tmp/server-init.${rand_rt}.$(date +%s 2>/dev/null || echo 0)"
  # [SEC-FIX] Use mkdir without -p
  if ! mkdir "$RUNTIME_DIR" 2>/dev/null; then
    if command -v mktemp >/dev/null 2>&1; then
      RUNTIME_DIR=$(mktemp -d /tmp/server-init.XXXXXX 2>/dev/null || echo "")
    fi
  fi
  [ -n "$RUNTIME_DIR" ] && [ -d "$RUNTIME_DIR" ] || { echo "FATAL: Cannot create runtime directory" >&2; exit 1; }
fi
chmod 700 "$RUNTIME_DIR" 2>/dev/null || true

STATE_FILE="$RUNTIME_DIR/state-$(id -u)"
LOCK_DIR="$RUNTIME_DIR/locks-$(id -u)"
# [v4.7.6 FIX-HIGH-N1] Script-level mutex. Two concurrent invocations of
# this script can interleave-corrupt /etc/ssh/sshd_config (both rename
# drop-ins, both install managed blocks, one's rollback wipes the other's
# work). The lock is a directory (mkdir is atomic) holding the active PID.
# Cleared by cleanup_locks() on normal exit. Stale entries (PID gone) are
# auto-reclaimed by the next start.
SCRIPT_LOCK_DIR="$RUNTIME_DIR/script.lock"

[ -L "$STATE_FILE" ] && rm -f "$STATE_FILE" 2>/dev/null || true
if [ -e "$LOCK_DIR" ] && [ ! -d "$LOCK_DIR" ]; then
  rm -f "$LOCK_DIR" 2>/dev/null || true
fi

# [v4.7.6] Acquire script-level mutex. We do this BEFORE any state mutation
# (well before setup_rollback). If we fail to acquire, refuse to start.
if mkdir "$SCRIPT_LOCK_DIR" 2>/dev/null; then
  echo "$$" > "$SCRIPT_LOCK_DIR/pid" 2>/dev/null || true
else
  # Lock exists. Check if the holder is still alive.
  holder_pid=""
  if [ -r "$SCRIPT_LOCK_DIR/pid" ]; then
    holder_pid=$(head -1 "$SCRIPT_LOCK_DIR/pid" 2>/dev/null | tr -d '\n\r ')
  fi
  # [v4.7.7 FIX-MED] Liveness detection uses BOTH /proc/$pid AND kill -0.
  # The kill -0 fallback works in chroots without /proc (where the previous
  # form falsely declared "stale" → reclaim → two scripts both proceed →
  # sshd_config corruption). The unknown-result third branch refuses rather
  # than racing.
  holder_alive="unknown"
  if [ -n "$holder_pid" ]; then
    if [ -d "/proc/$holder_pid" ]; then
      holder_alive="yes"
    elif kill -0 "$holder_pid" 2>/dev/null; then
      holder_alive="yes"
    elif [ -d "/proc/1" ] || command -v kill >/dev/null 2>&1; then
      # /proc is available (or we have kill) AND neither method found the
      # PID → genuinely stale, safe to reclaim.
      holder_alive="no"
    fi
  fi
  case "$holder_alive" in
    yes)
      echo "FATAL: Another linux-ssh-init-sh run is in progress (PID $holder_pid)" >&2
      echo "       If you're sure it crashed, remove $SCRIPT_LOCK_DIR and retry." >&2
      exit 1 ;;
    no)
      rm -rf "$SCRIPT_LOCK_DIR" 2>/dev/null || true
      if ! mkdir "$SCRIPT_LOCK_DIR" 2>/dev/null; then
        echo "FATAL: Cannot acquire script lock at $SCRIPT_LOCK_DIR" >&2
        exit 1
      fi
      echo "$$" > "$SCRIPT_LOCK_DIR/pid" 2>/dev/null || true ;;
    unknown)
      # Cannot determine liveness (no /proc, no kill, or empty pid file).
      # Refuse rather than risk a concurrent-corruption race.
      echo "FATAL: Lock $SCRIPT_LOCK_DIR exists but liveness check is ambiguous" >&2
      echo "       (no /proc and/or empty PID file). Verify no other run is in" >&2
      echo "       progress, then remove $SCRIPT_LOCK_DIR manually and retry." >&2
      exit 1 ;;
  esac
fi

# [v4.7.8 FIX] The script-level mutex is acquired before argv parsing so
# concurrent invocations are blocked early. That also means every pre-rollback
# exit path (--help/--version, bad flags, root/preflight/input failures) must
# release it. Once setup_rollback() installs the real rollback trap, this
# lightweight cleanup trap is replaced.
early_cleanup_before_rollback() {
  [ -n "${STATE_FILE:-}" ] && rm -f "$STATE_FILE" 2>/dev/null || true
  [ -n "${ARTIFACT_MIRROR:-}" ] && rm -f "$ARTIFACT_MIRROR" 2>/dev/null || true
  [ -n "${LOCK_DIR:-}" ] && [ -d "$LOCK_DIR" ] && rm -rf "$LOCK_DIR" 2>/dev/null || true
  [ -n "${SCRIPT_LOCK_DIR:-}" ] && [ -d "$SCRIPT_LOCK_DIR" ] && rm -rf "$SCRIPT_LOCK_DIR" 2>/dev/null || true
  [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ] && rm -rf "$TMP_DIR" 2>/dev/null || true
  case "${RUNTIME_DIR:-}" in
    /tmp/*) [ -d "$RUNTIME_DIR" ] && rm -rf "$RUNTIME_DIR" 2>/dev/null || true ;;
  esac
}
trap 'early_cleanup_before_rollback' EXIT

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ---------------- Initialize Variables ----------------
TARGET_USER=""
SSH_PORT="22"
KEY_OK="n"
PORT_OPT="1"
KEY_TYPE=""
KEY_VAL=""
DO_UPDATE="n"
DO_BBR="n"
# [v4.7.1] Track whether THIS script run created the target user. Used so that
# finalize_user_password_policy does not wipe an existing admin's password.
USER_WAS_CREATED="n"
# [v4.7.2] Track whether sudo configuration succeeded for the (new) user.
# Used so that finalize_user_password_policy does not clear the password on
# a brand-new account that ALSO lacks sudo — that combo gives a key-only
# account with no admin privileges, which is rarely what the operator wanted.
SUDO_DEPLOYED="n"
# [v4.7.2] Surfaces "the target account is locked and cannot SSH right now"
# in print_final_summary + generate_health_report + audit_log. Otherwise the
# operator sees the success banner with the ssh command line and only later
# discovers the account is unusable.
ACCOUNT_LOCKED_REASON=""
# [v4.7.4] "Should record_last_applied persist SELINUX_PORT=N for this run?"
# Set "y" by handle_selinux if NOOP/ADDED/MODIFIED (anything that means our
# port is currently labeled ssh_port_t).
SELINUX_LABEL_APPLIED="n"
# [v4.7.5] "Did THIS run install or retype the label, i.e. may rollback
# `semanage port -d` it without destroying pre-existing state?" "y" only on
# ADDED or MODIFIED paths; "n" on NOOP (label pre-existed independently).
SELINUX_LABEL_OWNED_BY_RUN="n"
# Note: a previous v4.7.5 draft introduced SELINUX_LABEL_PREEXISTED here, but
# the actual provenance signal that downstream code consumes is
# SELINUX_LABEL_OWNED_BY_RUN above (which is the inverse). The PREEXISTED
# flag is therefore intentionally NOT defined to avoid SC2034 unused-var.
OPENSSH_VER_MAJOR=0
OPENSSH_VER_MINOR=0

KEX_LINE=""
CIPHERS_LINE=""
MACS_LINE=""
CRYPTO_MODE="skip"
IPV6_ENABLED="n"
ROOT_KEY_PRESENT="n"
SUPPORTS_KBD_INTERACTIVE="n"

# ---------------- Automation Variables ----------------
ARG_USER=""
ARG_PORT=""
ARG_KEY_TYPE=""
ARG_KEY_VAL=""
ARG_UPDATE=""
ARG_BBR=""
AUTO_CONFIRM="n"
STRICT_MODE="n"
ARG_DELAY_RESTART="n"
ARG_NO_IP_PROBE="n"

# Parse Arguments
# [v4.7.6 FIX-MED] Track first-set state so duplicate --user / --port /
# --key-* don't silently last-win. Operators copy-pasting CI templates can
# unintentionally specify both --key-gh and --key-raw; refuse instead.
__seen_user=""; __seen_port=""; __seen_key=""
for a in "$@"; do
  case "$a" in
    --lang=zh)     LANG_CUR="zh" ;;
    --lang=en)     LANG_CUR="en" ;;
    --strict)      STRICT_MODE="y" ;;
    --yes)         AUTO_CONFIRM="y" ;;
    --user=*)
      if [ -n "$__seen_user" ]; then
        printf '[FATAL] --user specified more than once\n' >&2; exit 1
      fi
      __seen_user="y"; ARG_USER="${a#*=}" ;;
    --port=random)
      if [ -n "$__seen_port" ]; then
        printf '[FATAL] --port specified more than once\n' >&2; exit 1
      fi
      __seen_port="y"; ARG_PORT="random" ;;
    --port=*)
      if [ -n "$__seen_port" ]; then
        printf '[FATAL] --port specified more than once\n' >&2; exit 1
      fi
      __seen_port="y"; ARG_PORT="${a#*=}" ;;
    --key-gh=*)
      if [ -n "$__seen_key" ]; then
        printf '[FATAL] only one of --key-gh / --key-url / --key-raw may be given\n' >&2; exit 1
      fi
      __seen_key="y"; ARG_KEY_TYPE="gh";  ARG_KEY_VAL="${a#*=}" ;;
    --key-url=*)
      if [ -n "$__seen_key" ]; then
        printf '[FATAL] only one of --key-gh / --key-url / --key-raw may be given\n' >&2; exit 1
      fi
      __seen_key="y"; ARG_KEY_TYPE="url"; ARG_KEY_VAL="${a#*=}" ;;
    --key-raw=*)
      if [ -n "$__seen_key" ]; then
        printf '[FATAL] only one of --key-gh / --key-url / --key-raw may be given\n' >&2; exit 1
      fi
      __seen_key="y"
      ARG_KEY_TYPE="raw"
      # [v4.7.0] Interpret literal \n / \t in argv so multi-line keys can be
      # passed as a single shell-quoted argument.
      # [v4.7.3 FIX-MED] Reject \c and \0 escapes BEFORE printf %b — `\c`
      # would silently truncate the rest of the key material. Real SSH keys
      # never contain these, so refusal is safe.
      # [v4.7.4 FIX-LOW] Cannot use die() here — argv parsing runs BEFORE
      # function definitions; an undefined die call would "command not found"
      # silently and proceed (bypassing the check). Use raw printf+exit.
      __raw_in="${a#*=}"
      case "$__raw_in" in
        *'\c'*|*'\0'*)
          printf '[FATAL] Refusing --key-raw containing \\c or \\0 escape (truncation hazard)\n' >&2
          exit 1 ;;
      esac
      ARG_KEY_VAL="$(printf '%b' "$__raw_in")"
      unset __raw_in
      ;;
    --update)      ARG_UPDATE="y" ;;
    --no-update)   ARG_UPDATE="n" ;;
    --bbr)         ARG_BBR="y" ;;
    --no-bbr)      ARG_BBR="n" ;;
    --delay-restart) ARG_DELAY_RESTART="y" ;;
    --no-ip-probe) ARG_NO_IP_PROBE="y" ;;
    --version|-V)
      echo "linux-ssh-init-sh v4.7.8 Enterprise Hardening"
      # [v4.7.1] Clean up tmp/runtime dirs created at script entry so that
      # scripted `--version` invocations don't accumulate empty directories.
      [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ] && rm -rf "$TMP_DIR" 2>/dev/null
      [ -n "${RUNTIME_DIR:-}" ] && [ -d "$RUNTIME_DIR" ] && case "$RUNTIME_DIR" in /tmp/*) rm -rf "$RUNTIME_DIR" 2>/dev/null ;; esac
      exit 0 ;;
    --help|-h)
      cat <<EOF
linux-ssh-init-sh v4.7.8 — Server Init & SSH Hardening

USAGE:
  ./init.sh [OPTIONS]

CONTROL:
  --lang=zh|en          Force locale (default: zh)
  --yes                 Skip the final "proceed?" prompt
  --strict              Abort on any critical failure (no fallback)
  --delay-restart       Write config but do not restart sshd / run tests
  --no-ip-probe         Skip public IP lookup (offline-friendly)
  -V, --version         Print version and exit
  -h, --help            This help

USER & PORT:
  --user=NAME           Login user (default: deploy; "root" allowed)
  --port=22|random|N    SSH port (random uses 49152-65535)

KEY SOURCE (pick one):
  --key-gh=USERNAME     Pull from https://github.com/USERNAME.keys
  --key-url=URL         Fetch from URL (https://; http:// only outside strict)
  --key-raw="ssh-..."   Inline key(s); use literal \\n between multiple lines

SYSTEM:
  --update / --no-update    Upgrade installed packages
  --bbr    / --no-bbr       Enable TCP BBR congestion control

LOGS:
  /var/log/server-init.log         (debug log)
  /var/log/server-init-audit.log   (audit trail)
  /var/log/server-init-health.log  (post-run snapshot)
  /var/backups/ssh-config/<TS>/    (restore.sh per-run)
EOF
      # [v4.7.1] Same tmp-dir cleanup as --version.
      [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ] && rm -rf "$TMP_DIR" 2>/dev/null
      [ -n "${RUNTIME_DIR:-}" ] && [ -d "$RUNTIME_DIR" ] && case "$RUNTIME_DIR" in /tmp/*) rm -rf "$RUNTIME_DIR" 2>/dev/null ;; esac
      exit 0 ;;
  esac
done

# [v4.7.6 FIX-LOW] Reject empty --port=, --key-* values explicitly.
# Without this, `--port= --yes` falls through to interactive prompt → EOF →
# default to port 22 → silent hardening downgrade.
if [ "${__seen_port:-}" = "y" ] && [ -z "$ARG_PORT" ]; then
  printf '[FATAL] --port= requires a value (22, random, or 1024-65535)\n' >&2; exit 1
fi
if [ -n "$ARG_KEY_TYPE" ] && [ -z "$ARG_KEY_VAL" ]; then
  printf '[FATAL] --key-%s= requires a value\n' "$ARG_KEY_TYPE" >&2; exit 1
fi
unset __seen_user __seen_port __seen_key

# ---------------- Internationalization ----------------
msg() {
  key="$1"
  if [ "$LANG_CUR" = "zh" ]; then
    case "$key" in
      MUST_ROOT)    echo "必须以 root 权限运行此脚本" ;;
      BANNER)       echo "服务器初始化 & SSH 安全加固 (v4.7.8 Enterprise Hardening)" ;;
      STRICT_ON)    echo "STRICT 模式已开启：任何关键错误将直接退出" ;;
      ASK_USER)     echo "SSH 登录用户 (默认 " ;;
      ERR_USER_INV) echo "❌ 用户名无效 (仅限小写字母/数字/下划线，且避开系统保留名)" ;;
      ASK_PORT_T)   echo "SSH 端口配置：" ;;
      OPT_PORT_1)   echo "1) 使用 22 (默认)" ;;
      OPT_PORT_2)   echo "2) 随机高端口 (49152+, 自动避开 K8s)" ;;
      OPT_PORT_3)   echo "3) 手动指定" ;;
      SELECT)       echo "请选择 [1-3]: " ;;
      INPUT_PORT)   echo "请输入端口号 (1024-65535): " ;;
      PORT_ERR)     echo "❌ 端口输入无效 (非数字或超范围)" ;;
      PORT_RES)     echo "❌ 端口被系统保留或不建议使用 (如 80, 443, 3306 等)" ;;
      PORT_K8S)     echo "⚠️  警告: 此端口位于 Kubernetes NodePort 常用范围 (30000-32767)，可能冲突" ;;
      ASK_KEY_T)    echo "SSH 公钥来源：" ;;
      OPT_KEY_1)    echo "1) GitHub 用户导入" ;;
      OPT_KEY_2)    echo "2) URL 下载" ;;
      OPT_KEY_3)    echo "3) 手动粘贴" ;;
      INPUT_GH)     echo "请输入 GitHub 用户名: " ;;
      INPUT_URL)    echo "请输入公钥 URL: " ;;
      INPUT_RAW)    echo "请粘贴公钥内容 (空行结束输入): " ;;
      ASK_UPD)      echo "是否更新系统软件包? [y/n] (默认 n): " ;;
      ASK_BBR)      echo "是否开启 BBR 加速? [y/n] (默认 n): " ;;
      CONFIRM_T)    echo "---------------- 执行确认 ----------------" ;;
      C_USER)       echo "登录用户: " ;;
      C_PORT)       echo "端口模式: " ;;
      C_KEY)        echo "密钥来源: " ;;
      C_UPD)        echo "系统更新: " ;;
      C_BBR)        echo "开启 BBR: " ;;
      WARN_FW)      echo "⚠ 注意：修改端口前，请确认云厂商防火墙/安全组已放行对应 TCP 端口" ;;
      ASK_SURE)     echo "确认执行? [y/n]: " ;;
      CANCEL)       echo "已取消操作" ;;
      I_INSTALL)    echo "正在安装基础依赖..." ;;
      I_UPD)        echo "正在更新系统..." ;;
      I_BBR)        echo "正在配置 BBR..." ;;
      I_USER)       echo "正在配置用户..." ;;
      I_SSH_INSTALL) echo "未检测到 OpenSSH，正在安装..." ;;
      I_KEY_OK)     echo "公钥部署成功" ;;
      W_KEY_FAIL)   echo "公钥部署失败，将启用安全回退策略以避免失联" ;;
      I_BACKUP)     echo "已全量备份配置 (SSH/User/Firewall): " ;;
      E_SSHD_CHK)   echo "sshd 配置校验失败，正在回滚..." ;;
      E_GREP_FAIL)  echo "配置验证失败：关键参数未生效，正在回滚..." ;;
      E_RESTART)    echo "SSH 服务重启失败，正在回滚..." ;;
      W_RESTART)    echo "无法自动重启 SSH 服务，请手动重启" ;;
      W_LISTEN_FAIL) echo "SSHD 已重启但端口未监听，可能启动失败，正在回滚..." ;;
      DONE_T)       echo "================ 完成 ================" ;;
      DONE_MSG1)    echo "请【不要关闭】当前窗口。" ;;
      DONE_MSG2)    echo "请新开一个终端窗口测试登录：" ;;
      DONE_FW)      echo "⚠ 若无法连接，请再次检查防火墙设置" ;;
      AUTO_SKIP)    echo "检测到参数输入，跳过询问: " ;;
      RB_START)     echo "脚本执行出现关键错误，开始自动回滚..." ;;
      RB_DONE)      echo "回滚完成。系统状态已恢复。" ;;
      RB_FAIL)      echo "致命错误：回滚失败！请立即手动检查 /etc/ssh/sshd_config" ;;
      SELINUX_DET)  echo "检测到 SELinux Enforcing 模式，正在配置端口规则..." ;;
      SELINUX_OK)   echo "SELinux 端口规则添加成功" ;;
      SELINUX_FAIL) echo "SELinux 规则添加失败，请手动执行: semanage port -a -t ssh_port_t -p tcp PORT" ;;
      SELINUX_INS)  echo "正在安装 SELinux 管理工具..." ;;
      CLEAN_D)      echo "检测到冲突的配置片段，已备份并移除: " ;;
      TEST_CONN)    echo "正在进行 SSH 连接测试 (IPv4/Local)..." ;;
      TEST_OK)      echo "SSH 连接测试通过" ;;
      TEST_FAIL)    echo "SSH 连接测试全部失败！新配置可能无法连接，正在回滚..." ;;
      IPV6_CFG)     echo "检测到全局 IPv6 环境，已添加 :: 监听支持" ;;
      SYS_PROT)     echo "正在添加 systemd 服务防误杀保护..." ;;
      MOTD_UPD)     echo "正在更新登录提示信息 (MotD)..." ;;
      COMPAT_WARN)  echo "检测到兼容性限制，已自动调整配置..." ;;
      AUDIT_START)  echo "开始执行审计记录..." ;;
      BOX_TITLE)    echo "初始化完成 - 安全配置已生效" ;;
      BOX_SSH)      echo "SSH 连接信息:" ;;
      BOX_KEY_ON)   echo "🔐 密钥认证: 已启用 (密码登录已禁用)" ;;
      BOX_KEY_OFF)  echo "⚠️ 密钥认证: 未启用 (密码登录保持可用/回退策略已启用)" ;;
      BOX_PORT)     echo "📍 端口变更: 22 → " ;;
      BOX_FW)       echo "⚠️  请确认防火墙已开放 TCP 端口" ;;
      BOX_WARN)     echo "重要: 请在新窗口中测试连接，确认成功后再关闭此窗口！" ;;
      BOX_K8S_WARN) echo "⚠️  注意: 使用了 Kubernetes NodePort 范围端口" ;;
      ERR_MISSING)  echo "❌ 缺少必要命令，无法继续: " ;;
      ERR_MISSING_SSHD) echo "❌ 未找到 sshd 命令，请先安装 OpenSSH Server" ;;
      WARN_DISK)    echo "⚠️  磁盘空间不足: " ;;
      WARN_MEM)     echo "⚠️  可用内存不足: " ;;
      WARN_RESUME)  echo "检测到未完成的初始化，可能上次执行异常终止" ;;
      ASK_RESUME)   echo "检测到未完成的操作，是否继续? [y/N]: " ;;
      ERR_BACKUP_DIR) echo "❌ 无法创建备份目录:" ;;
      ERR_BACKUP_DIR_ALT) echo "❌ 无法创建备用备份目录" ;;
      ERR_BACKUP_SUBDIR) echo "❌ 无法创建备份子目录:" ;;
      INFO_BACKUP_CREATED) echo "✅ 备份已创建:" ;;
      INFO_CLEANING_BACKUPS) echo "🧹 正在清理" ;;
      INFO_OLD_BACKUPS) echo "个旧备份..." ;;
      ERR_LOCK_DIR) echo "❌ 无法创建锁目录:" ;;
      WARN_LOCK_DIR_PERM) echo "⚠️ 无法设置锁目录权限，继续尝试..." ;;
      WARN_CLEAN_LOCKS) echo "⚠️ 清理旧的锁文件..." ;;
      WARN_INVALID_KEY) echo "⚠️ 跳过无效的SSH密钥行" ;;
      WARN_SHORT_RSA_KEY) echo "⚠️ RSA密钥过短:" ;;
      WARN_SHORT_ED25519_KEY) echo "⚠️ Ed25519密钥过短:" ;;
      WARN_SHORT_DSA_KEY) echo "⚠️ DSA密钥过短:" ;;
      ERR_INVALID_KEY_FORMAT) echo "❌ SSH密钥格式无效" ;;
      ERR_MISSING_BASE64) echo "❌ SSH密钥缺少base64部分" ;;
      ERR_INVALID_BASE64) echo "❌ SSH密钥base64编码无效" ;;
      WARN_NO_BASE64_SKIPLEN) echo "⚠️ 未检测到 base64 命令：将跳过密钥长度校验，仅做格式校验" ;;
      WARN_USER_SHELL) echo "⚠️ 用户shell不允许登录:" ;;
      ASK_CHANGE_SHELL) echo "是否更改用户的shell为/bin/bash? [y/N]: " ;;
      WARN_CHANGE_SHELL_FAIL) echo "⚠️ 更改shell失败" ;;
      WARN_UNUSUAL_SHELL) echo "⚠️ 用户使用非常规shell:" ;;
      WARN_HOME_OWNER) echo "⚠️ 用户家目录所有者异常:" ;;
      WARN_HOME_NOT_WRITABLE) echo "⚠️ 用户家目录不可写" ;;
      ERR_USER_CREATE_FAIL) echo "❌ 创建用户失败" ;;
      ERR_USER_VERIFY_FAIL) echo "❌ 用户创建后验证失败" ;;
      WARN_NO_SUDOERS_DIR) echo "⚠️ 没有/etc/sudoers.d目录，跳过sudo配置" ;;
      INFO_SUDO_EXISTS) echo "ℹ️ 用户已配置sudo权限" ;;
      ERR_SUDOERS_SYNTAX) echo "❌ sudoers文件语法错误，已删除" ;;
      ERR_SUDOERS_PERM) echo "❌ 无法设置sudoers文件权限" ;;
      INFO_SUDO_CONFIGURED) echo "✅ 为用户配置了sudo权限" ;;
      WARN_SSH_PROTOCOL) echo "⚠️ SSH协议握手失败或超时" ;;
      INFO_SSH_PROTOCOL_OK) echo "✅ SSH协议握手成功" ;;
      WARN_PORT_OPEN_BUT_FAIL) echo "⚠️ 端口已打开，但SSH客户端连接失败(通常因无私钥或默认私钥不匹配)。此非错误，请务必人工测试连接！" ;;
      WARN_X11_FORWARDING) echo "⚠️ X11转发已启用，可能存在安全风险" ;;
      WARN_EMPTY_PASSWORDS) echo "⚠️ 允许空密码，存在安全风险" ;;
      WARN_INSECURE_OPTIONS) echo "⚠️ 检测到非关键的不安全选项 (仅提示，不影响安装)" ;;
      ERR_DEADLOCK) echo "❌ 致命错误：密码和密钥认证同时被禁用，将导致锁定！" ;;
      ERR_PASSWORD_NO_KEY) echo "❌ 致命错误：密码认证已禁用但未成功部署SSH密钥" ;;
      ERR_ROOT_NO_KEY) echo "❌ 致命错误：root密码登录已禁用但未部署SSH密钥" ;;
      WARN_PORT_MISMATCH) echo "⚠️ 配置中的端口与目标端口不匹配" ;;
      ERR_CANNOT_RESERVE_PORT) echo "❌ 无法预留端口，端口可能已被占用" ;;
      INFO_OLD_SSH_SKIP_ALGO) echo "ℹ️ OpenSSH较旧或无法检测支持列表：跳过现代加密算法强制配置" ;;
      INFO_SANITIZE_DUP) echo "ℹ️ 清理原配置文件中的重复指令..." ;;
      INFO_MATCH_INSERT) echo "ℹ️ 检测到 Match 块：托管配置将插入到首个 Match 之前，以避免语法/作用域问题" ;;
      ERR_NO_BANNER) echo "❌ 未能获取 SSH-2.0 协议 banner，服务可能未正常启动" ;;
      INFO_KEYS_DEPLOYED) echo "✅ 成功部署密钥数量:" ;;
      WARN_NO_VALID_KEYS) echo "⚠️ 没有有效的SSH密钥被部署" ;;
      ERR_HOME_SYMLINK) echo "❌ 拒绝：用户家目录是符号链接" ;;
      ERR_SSH_DIR_SYMLINK) echo "❌ 拒绝：.ssh 目录是符号链接" ;;
      ERR_AUTH_KEYS_SYMLINK) echo "❌ 拒绝：authorized_keys 是符号链接" ;;
      ERR_HOME_NOT_DIR) echo "❌ 拒绝：用户家目录不是目录" ;;
      ERR_SSH_DIR_NOT_DIR) echo "❌ 拒绝：.ssh 存在但不是目录" ;;
      ERR_AUTH_KEYS_NOT_FILE) echo "❌ 拒绝：authorized_keys 存在但不是普通文件" ;;
      DELAY_RESTART_MSG) echo "⚠️ 延迟重启模式：配置已写入，请手动重启 sshd 并测试连接" ;;
      *) echo "$key" ;;
    esac
  else
    case "$key" in
      MUST_ROOT)    echo "Must be run as root" ;;
      BANNER)       echo "Server Init & SSH Hardening (v4.7.8 Enterprise Hardening)" ;;
      STRICT_ON)    echo "STRICT mode ON: Critical errors will abort" ;;
      ASK_USER)     echo "SSH Login User (default " ;;
      ERR_USER_INV) echo "❌ Invalid username (lowercase/digits/underscore only, no reserved words)" ;;
      ASK_PORT_T)   echo "SSH Port Configuration:" ;;
      OPT_PORT_1)   echo "1) Use 22 (Default)" ;;
      OPT_PORT_2)   echo "2) Random High Port (49152+, avoids K8s)" ;;
      OPT_PORT_3)   echo "3) Manual Input" ;;
      SELECT)       echo "Select [1-3]: " ;;
      INPUT_PORT)   echo "Enter Port (1024-65535): " ;;
      PORT_ERR)     echo "❌ Invalid port (not numeric or out of range)" ;;
      PORT_RES)     echo "❌ Port is reserved (e.g. 80, 443, 3306)" ;;
      PORT_K8S)     echo "⚠️  Warning: Port falls in Kubernetes NodePort range (30000-32767)" ;;
      ASK_KEY_T)    echo "SSH Public Key Source:" ;;
      OPT_KEY_1)    echo "1) GitHub User" ;;
      OPT_KEY_2)    echo "2) URL Download" ;;
      OPT_KEY_3)    echo "3) Manual Paste" ;;
      INPUT_GH)     echo "Enter GitHub Username: " ;;
      INPUT_URL)    echo "Enter Key URL: " ;;
      INPUT_RAW)    echo "Paste Key (Empty line to finish): " ;;
      ASK_UPD)      echo "Update system packages? [y/n] (default n): " ;;
      ASK_BBR)      echo "Enable TCP BBR? [y/n] (default n): " ;;
      CONFIRM_T)    echo "---------------- Confirmation ----------------" ;;
      C_USER)       echo "User: " ;;
      C_PORT)       echo "Port: " ;;
      C_KEY)        echo "Key Source: " ;;
      C_UPD)        echo "Update: " ;;
      C_BBR)        echo "Enable BBR: " ;;
      WARN_FW)      echo "⚠ WARNING: Ensure Cloud Firewall/Security Group allows the new TCP port" ;;
      ASK_SURE)     echo "Proceed? [y/n]: " ;;
      CANCEL)       echo "Cancelled." ;;
      I_INSTALL)    echo "Installing dependencies..." ;;
      I_UPD)        echo "Updating system..." ;;
      I_BBR)        echo "Configuring BBR..." ;;
      I_USER)       echo "Configuring user..." ;;
      I_SSH_INSTALL) echo "OpenSSH not found, installing..." ;;
      I_KEY_OK)     echo "SSH Key deployed successfully" ;;
      W_KEY_FAIL)   echo "Key deployment failed; enabling fallback policy to avoid lockout" ;;
      I_BACKUP)     echo "Full backup created (SSH/User/Firewall): " ;;
      E_SSHD_CHK)   echo "sshd config validation failed, rolling back..." ;;
      E_GREP_FAIL)  echo "Config validation failed: Critical settings not active. Rolling back..." ;;
      E_RESTART)    echo "SSH service restart failed, rolling back..." ;;
      W_RESTART)    echo "Could not restart sshd automatically. Please restart manually." ;;
      W_LISTEN_FAIL) echo "SSHD restarted but port is not listening. Rolling back..." ;;
      DONE_T)       echo "================ DONE ================" ;;
      DONE_MSG1)    echo "Please DO NOT close this window yet." ;;
      DONE_MSG2)    echo "Open a NEW terminal to test login:" ;;
      DONE_FW)      echo "⚠ If connection fails, check your Firewall settings." ;;
      AUTO_SKIP)    echo "Argument detected, skipping prompt: " ;;
      RB_START)     echo "Critical error. Starting automatic rollback..." ;;
      RB_DONE)      echo "Rollback complete. System state restored." ;;
      RB_FAIL)      echo "FATAL: Rollback failed! Manually check /etc/ssh/sshd_config" ;;
      SELINUX_DET)  echo "SELinux Enforcing detected. Configuring port rules..." ;;
      SELINUX_OK)   echo "SELinux port rule added successfully." ;;
      SELINUX_FAIL) echo "SELinux rule failed. Manually run: semanage port -a -t ssh_port_t -p tcp PORT" ;;
      SELINUX_INS)  echo "Installing SELinux management tools..." ;;
      CLEAN_D)      echo "Detected conflicting config fragment, backed up and removed: " ;;
      TEST_CONN)    echo "Testing SSH connection (IPv4/Local)..." ;;
      TEST_OK)      echo "SSH connection test passed." ;;
      TEST_FAIL)    echo "SSH connection test FAILED! Rolling back..." ;;
      IPV6_CFG)     echo "Global IPv6 detected. Added listen address :: support." ;;
      SYS_PROT)     echo "Adding systemd service protection (anti-kill)..." ;;
      MOTD_UPD)     echo "Updating Message of the Day (MotD)..." ;;
      COMPAT_WARN)  echo "Compatibility limits detected; adjusted configuration automatically..." ;;
      AUDIT_START)  echo "Starting audit logging..." ;;
      BOX_TITLE)    echo "Init Complete - Security Applied" ;;
      BOX_SSH)      echo "SSH Connection Info:" ;;
      BOX_KEY_ON)   echo "🔐 Key Auth: ENABLED (Password Disabled)" ;;
      BOX_KEY_OFF)  echo "⚠️ Key Auth: DISABLED (Password/Fallback Enabled)" ;;
      BOX_PORT)     echo "📍 Port Change: 22 → " ;;
      BOX_FW)       echo "⚠️  Verify Firewall Open for TCP Port" ;;
      BOX_WARN)     echo "IMPORTANT: Test connection in NEW window before closing this one!" ;;
      BOX_K8S_WARN) echo "⚠️  NOTE: Using K8s NodePort range" ;;
      ERR_MISSING)  echo "❌ Missing essential commands: " ;;
      ERR_MISSING_SSHD) echo "❌ sshd command not found, please install OpenSSH Server first" ;;
      WARN_DISK)    echo "⚠️  Low disk space: " ;;
      WARN_MEM)     echo "⚠️  Low memory: " ;;
      WARN_RESUME)  echo "Detected incomplete initialization, last execution may have crashed" ;;
      ASK_RESUME)   echo "Detected incomplete operation, continue? [y/N]: " ;;
      ERR_BACKUP_DIR) echo "❌ Cannot create backup directory:" ;;
      ERR_BACKUP_DIR_ALT) echo "❌ Cannot create alternative backup directory" ;;
      ERR_BACKUP_SUBDIR) echo "❌ Cannot create backup subdirectory:" ;;
      INFO_BACKUP_CREATED) echo "✅ Backup created:" ;;
      INFO_CLEANING_BACKUPS) echo "🧹 Cleaning" ;;
      INFO_OLD_BACKUPS) echo "old backups..." ;;
      ERR_LOCK_DIR) echo "❌ Cannot create lock directory:" ;;
      WARN_LOCK_DIR_PERM) echo "⚠️ Cannot set lock directory permissions, continuing..." ;;
      WARN_CLEAN_LOCKS) echo "⚠️ Cleaning old lock files..." ;;
      WARN_INVALID_KEY) echo "⚠️ Skipping invalid SSH key line" ;;
      WARN_SHORT_RSA_KEY) echo "⚠️ RSA key too short:" ;;
      WARN_SHORT_ED25519_KEY) echo "⚠️ Ed25519 key too short:" ;;
      WARN_SHORT_DSA_KEY) echo "⚠️ DSA key too short:" ;;
      ERR_INVALID_KEY_FORMAT) echo "❌ SSH key format invalid" ;;
      ERR_MISSING_BASE64) echo "❌ SSH key missing base64 part" ;;
      ERR_INVALID_BASE64) echo "❌ SSH key base64 encoding invalid" ;;
      WARN_NO_BASE64_SKIPLEN) echo "⚠️ base64 not found: skipping key length checks (format-only validation)" ;;
      WARN_USER_SHELL) echo "⚠️ User shell does not allow login:" ;;
      ASK_CHANGE_SHELL) echo "Change user's shell to /bin/bash? [y/N]: " ;;
      WARN_CHANGE_SHELL_FAIL) echo "⚠️ Failed to change shell" ;;
      WARN_UNUSUAL_SHELL) echo "⚠️ User uses unusual shell:" ;;
      WARN_HOME_OWNER) echo "⚠️ User home directory owner mismatch:" ;;
      WARN_HOME_NOT_WRITABLE) echo "⚠️ User home directory not writable" ;;
      ERR_USER_CREATE_FAIL) echo "❌ Failed to create user" ;;
      ERR_USER_VERIFY_FAIL) echo "❌ User verification failed after creation" ;;
      WARN_NO_SUDOERS_DIR) echo "⚠️ No /etc/sudoers.d directory, skipping sudo config" ;;
      INFO_SUDO_EXISTS) echo "ℹ️ User already has sudo permissions" ;;
      ERR_SUDOERS_SYNTAX) echo "❌ sudoers file syntax error, deleted" ;;
      ERR_SUDOERS_PERM) echo "❌ Cannot set sudoers file permissions" ;;
      INFO_SUDO_CONFIGURED) echo "✅ Configured sudo permissions for user" ;;
      WARN_SSH_PROTOCOL) echo "⚠️ SSH protocol handshake failed or timed out" ;;
      INFO_SSH_PROTOCOL_OK) echo "✅ SSH protocol handshake successful" ;;
      WARN_PORT_OPEN_BUT_FAIL) echo "⚠️ Port is open, but SSH connection failed (likely due to missing/mismatched private key). This is NOT an error. Please verify connection manually!" ;;
      WARN_X11_FORWARDING) echo "⚠️ X11 forwarding enabled, potential security risk" ;;
      WARN_EMPTY_PASSWORDS) echo "⚠️ Empty passwords allowed, security risk" ;;
      WARN_INSECURE_OPTIONS) echo "⚠️ Found non-critical insecure options (Info only, proceeding)" ;;
      ERR_DEADLOCK) echo "❌ FATAL: Both password and key authentication disabled, will cause lockout!" ;;
      ERR_PASSWORD_NO_KEY) echo "❌ FATAL: Password auth disabled but no SSH key deployed" ;;
      ERR_ROOT_NO_KEY) echo "❌ FATAL: Root password login disabled but no SSH key deployed" ;;
      WARN_PORT_MISMATCH) echo "⚠️ Port in config does not match target port" ;;
      ERR_CANNOT_RESERVE_PORT) echo "❌ Cannot reserve port, port may be occupied" ;;
      INFO_OLD_SSH_SKIP_ALGO) echo "ℹ️ Old OpenSSH or unable to detect supported lists: skipping forced crypto algorithms" ;;
      INFO_SANITIZE_DUP) echo "ℹ️ Sanitizing duplicate directives in original config..." ;;
      INFO_MATCH_INSERT) echo "ℹ️ Match blocks detected: inserting managed block before first Match to avoid scope issues" ;;
      ERR_NO_BANNER) echo "❌ Failed to get SSH-2.0 protocol banner, service may not be running properly" ;;
      INFO_KEYS_DEPLOYED) echo "✅ Number of keys deployed:" ;;
      WARN_NO_VALID_KEYS) echo "⚠️ No valid SSH keys were deployed" ;;
      ERR_HOME_SYMLINK) echo "❌ Refuse: user home is symlink" ;;
      ERR_SSH_DIR_SYMLINK) echo "❌ Refuse: .ssh is symlink" ;;
      ERR_AUTH_KEYS_SYMLINK) echo "❌ Refuse: authorized_keys is symlink" ;;
      ERR_HOME_NOT_DIR) echo "❌ Refuse: user home is not a directory" ;;
      ERR_SSH_DIR_NOT_DIR) echo "❌ Refuse: .ssh exists but is not a directory" ;;
      ERR_AUTH_KEYS_NOT_FILE) echo "❌ Refuse: authorized_keys exists but is not a regular file" ;;
      DELAY_RESTART_MSG) echo "⚠️ Delay restart mode: config written, please manually restart sshd and test" ;;
      *) echo "$key" ;;
    esac
  fi
}

# ---------------- Logging & Audit ----------------
init_log_files() {
  for logfile in "$LOG_FILE" "$AUDIT_FILE"; do
    # [v4.7.4 FIX-LOW] Reject pre-planted symlinks at log paths. A symlink
    # in /var/log (root-owned 755) requires prior root-equiv write, but as
    # defense-in-depth we remove it before touch follows it to e.g.
    # /etc/shadow. Helper unlink_if_symlink is defined later, so inline here.
    if [ -L "$logfile" ]; then
      rm -f "$logfile" 2>/dev/null || true
    fi
    if [ -f "$logfile" ]; then
      if [ ! -w "$logfile" ]; then
        logfile_new="${logfile}.$(date +%s)"
        if touch "$logfile_new" 2>/dev/null; then
          chmod 600 "$logfile_new" 2>/dev/null || true
          if [ "$logfile" = "$LOG_FILE" ]; then
            LOG_FILE="$logfile_new"
          else
            AUDIT_FILE="$logfile_new"
          fi
        fi
      fi
    else
      touch "$logfile" 2>/dev/null || true
      chmod 600 "$logfile" 2>/dev/null || true
    fi
  done
}

init_log_files

log() { echo "$(date '+%F %T') $*" >>"$LOG_FILE" 2>/dev/null || true; }

audit_log() {
  action="$1"
  details="$2"
  # [v4.7.6 FIX-HIGH-N3] Strip newlines from action/details before writing.
  # Without this, a $details value containing "\n---\nACTION: FAKE" could
  # inject forged audit entries. $details can transitively come from
  # untrusted sources (e.g. paths derived from /etc/passwd field 6 which
  # ends up in KEYS_DEPLOYED "auth=..." details). Replace LF/CR with space.
  action=$(printf '%s' "$action" | tr -d '\n\r')
  details=$(printf '%s' "$details" | tr '\n\r' '  ')
  {
    echo "=== $(date '+%F %T') ==="
    echo "ACTION: $action"
    echo "USER: $(whoami 2>/dev/null || echo root)"
    echo "DETAILS: $details"
    echo "---"
  } >> "$AUDIT_FILE" 2>/dev/null || {
    # [v4.7.7 FIX-LOW] Audit-log fallback to stderr when /var/log is full,
    # read-only, or otherwise unwritable. The ROLLBACK entry itself is the
    # most important forensic record — losing it silently would leave the
    # operator with no idea why the rollback fired.
    printf 'AUDIT-FALLBACK %s ACTION=%s DETAILS=%s\n' \
      "$(date '+%F %T' 2>/dev/null || echo unknown)" "$action" "$details" >&2
  }
  log "[AUDIT] $action - $details"
}

# [v4.7.0] Color via printf %b (dash-safe: '\033[...' is interpreted, not literal)
# IMPORTANT: never put $COLOR into the format-string slot — keep it as %b argument.
info() { printf '%b[INFO]%b %s\n' "$BLUE"   "$NC" "$*"; log "[INFO] $*"; }
warn() { printf '%b[WARN]%b %s\n' "$YELLOW" "$NC" "$*"; log "[WARN] $*"; }
err()  { printf '%b[ERR ]%b %s\n' "$RED"    "$NC" "$*"; log "[ERR ] $*"; }
ok()   { printf '%b[ OK ]%b %s\n' "$GREEN"  "$NC" "$*"; log "[OK] $*"; }
die() { err "$*"; exit 1; }

# [v4.7.4 FIX-LOW] Symlink-defense helper: if $1 is a symlink, remove it.
# Prevents a planted symlink (planted by a previous root-equiv compromise)
# from making `cat > FILE` or `echo >> FILE` write into the symlink target
# (e.g. /etc/shadow). All write-targets in root-only directories use this.
unlink_if_symlink() {
  [ -L "$1" ] || return 0
  rm -f "$1" 2>/dev/null || true
}

# [v4.7.7 FIX-HIGH] Detect chroot-without-PID-namespace. Used by:
#   - direct-spawn sshd refusal (avoid `pkill -x sshd` killing host sshd)
#   - script-level mutex stale-PID detection (without /proc we can't tell
#     "stale lock" from "live peer", so refuse rather than reclaim)
# Returns 0 if chroot/ambiguous, 1 if confirmed real root.
in_chroot_or_unknown() {
  # If /proc is unavailable, we can't determine — treat as chroot for safety.
  [ -d /proc/1/root ] || return 0
  # Compare root inode of the script's view vs PID 1's root.
  root_now=$(stat -c '%d:%i' / 2>/dev/null)
  root_init=$(stat -c '%d:%i' /proc/1/root/ 2>/dev/null)
  [ -z "$root_now" ] || [ -z "$root_init" ] && return 0
  [ "$root_now" != "$root_init" ]
}

# =========================================================
# Core Logic Functions
# =========================================================

preflight_checks() {
  essential_cmds="cat grep awk sed cp mv chmod chown mkdir rm id"
  extended_cmds="wc tr head cut touch find sleep date df uname tail"

  missing_cmds=""
  for cmd in $essential_cmds; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing_cmds="$missing_cmds $cmd"
    fi
  done
  if [ -n "$missing_cmds" ]; then
    die "$(msg ERR_MISSING)$missing_cmds"
  fi

  for cmd in $extended_cmds; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      warn "Optional command not found: $cmd (some features may be limited)"
    fi
  done

  available_kb=$(df -k / 2>/dev/null | awk 'NR==2 {print $4}' 2>/dev/null || echo "")
  if [ -n "$available_kb" ] && [ "$available_kb" -lt 5120 ] 2>/dev/null; then
    warn "$(msg WARN_DISK)${available_kb}KB"
  fi

  if [ -f /proc/meminfo ]; then
    mem_avail=$(grep MemAvailable /proc/meminfo 2>/dev/null | awk '{print $2}' 2>/dev/null || echo "")
    if [ -n "$mem_avail" ] && [ "$mem_avail" -lt 51200 ] 2>/dev/null; then
      warn "$(msg WARN_MEM)${mem_avail}KB"
    fi
  fi

  if ! command -v base64 >/dev/null 2>&1; then
    warn "$(msg WARN_NO_BASE64_SKIPLEN)"
  fi
}

# ---------------- Package Manager ----------------
detect_pm() {
  [ -f /etc/alpine-release ] && { echo apk; return; }
  [ -f /etc/debian_version ] && { echo apt; return; }
  [ -f /etc/redhat-release ] && { echo yum; return; }
  echo unknown
}

PM="$(detect_pm)"
APT_UPDATED="n"
APK_UPDATED="n"
YUM_PREPARED="n"

pm_prepare_once() {
  case "$PM" in
    apt) [ "$APT_UPDATED" != "y" ] && { apt-get update -y >>"$LOG_FILE" 2>&1 || true; APT_UPDATED="y"; } ;;
    apk) [ "$APK_UPDATED" != "y" ] && { apk update >>"$LOG_FILE" 2>&1 || true; APK_UPDATED="y"; } ;;
    yum) [ "$YUM_PREPARED" != "y" ] && {
         if command -v dnf >/dev/null 2>&1; then dnf makecache -y >>"$LOG_FILE" 2>&1 || true;
         else yum makecache -y >>"$LOG_FILE" 2>&1 || true; fi
         YUM_PREPARED="y"; } ;;
  esac
}

install_pkg() {
  case "$PM" in
    apt) pm_prepare_once; DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >>"$LOG_FILE" 2>&1 ;;
    yum) pm_prepare_once;
         if command -v dnf >/dev/null 2>&1; then dnf install -y "$@" >>"$LOG_FILE" 2>&1;
         else yum install -y "$@" >>"$LOG_FILE" 2>&1; fi ;;
    apk) pm_prepare_once; apk add --no-cache "$@" >>"$LOG_FILE" 2>&1 ;;
    *) return 1 ;;
  esac
}

install_pkg_try() {
  for p in "$@"; do
    if install_pkg "$p" >/dev/null 2>&1; then return 0; fi
  done
  return 1
}

update_system() {
  # [v4.7.8 FIX-MED W1-1] Forensic record: a system-wide package upgrade is a
  # significant mutation that prior versions did not audit. Operators
  # investigating post-incident need to know whether the run touched
  # packages.
  audit_log "SYSTEM_UPDATE_START" "pm=$PM"
  case "$PM" in
    apt) pm_prepare_once; DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >>"$LOG_FILE" 2>&1 ;;
    yum) pm_prepare_once;
         if command -v dnf >/dev/null 2>&1; then dnf upgrade -y >>"$LOG_FILE" 2>&1;
         else yum update -y >>"$LOG_FILE" 2>&1; fi ;;
    apk) pm_prepare_once; apk upgrade >>"$LOG_FILE" 2>&1 ;;
  esac
  audit_log "SYSTEM_UPDATE_DONE" "pm=$PM rc=$?"
}

# ---------------- SSHD Restart ----------------
# [v4.7.1] Args:
#   $1 (optional) — "force" bypasses the --delay-restart no-op (used by
#                   rollback_handler, which must always relaunch sshd).
restart_sshd() {
  force_mode="${1:-}"

  if [ "$ARG_DELAY_RESTART" = "y" ] && [ "$force_mode" != "force" ]; then
    warn "DELAY RESTART: Please manually restart sshd later."
    return 0
  fi

  # [v4.7.8 FIX-HIGH-W4] Detect chroot BEFORE the systemctl path. With /run/dbus
  # bind-mounted into the chroot (common), `systemctl restart sshd` would
  # cross the chroot boundary via D-Bus and restart the HOST's sshd using the
  # CHROOT's modified config — silently breaking the host. Previously the
  # chroot guard only fired inside the direct-spawn fallback (after systemctl
  # had already run). Move the guard to the top of the function.
  if in_chroot_or_unknown; then
    err "Refusing to restart sshd: this process appears to be in a chroot"
    err "  (or environment without /proc). Any restart path could reach the"
    err "  HOST's sshd via D-Bus/PID-NS leakage and apply this chroot's config"
    err "  to the host. Use --delay-restart and restart sshd manually outside"
    err "  the chroot."
    audit_log "RESTART_REFUSED" "reason=chroot_or_no_proc"
    return 1
  fi

  res=1

  # ----- 1. systemd -----
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop ssh.socket >/dev/null 2>&1 || true
    systemctl disable ssh.socket >/dev/null 2>&1 || true
    if systemctl restart sshd >>"$LOG_FILE" 2>&1 || systemctl restart ssh >>"$LOG_FILE" 2>&1; then
      return 0
    fi
    res=$?
  fi

  # ----- 2. OpenRC -----
  if command -v rc-service >/dev/null 2>&1; then
    rc-service sshd restart >>"$LOG_FILE" 2>&1 && return 0
    res=$?
  fi

  # ----- 3. SysV service -----
  if command -v service >/dev/null 2>&1; then
    service sshd restart >>"$LOG_FILE" 2>&1 && return 0
    service ssh  restart >>"$LOG_FILE" 2>&1 && return 0
    res=$?
  fi

  # ----- 4. init.d -----
  if [ -x /etc/init.d/sshd ]; then
    /etc/init.d/sshd restart >>"$LOG_FILE" 2>&1 && return 0
  fi
  if [ -x /etc/init.d/ssh  ]; then
    /etc/init.d/ssh  restart >>"$LOG_FILE" 2>&1 && return 0
  fi

  # ----- 5. [v4.7.1 FIX-R4/H5] Direct-spawn fallback for minimal containers,
  #          chroot environments, or any host where no init system is reachable
  #          but the sshd binary is present. This is what makes the script
  #          actually work inside e.g. a plain `docker run ubuntu:22.04` (which
  #          has no PID 1 systemd) and inside test containers in CI.
  if command -v sshd >/dev/null 2>&1; then
    # [v4.7.3 FIX-MED] If the operator is running over SSH, the direct-spawn
    # fallback would kill the operator's own session. Detect via SSH_CONNECTION
    # env var (present in interactive ssh sessions) and refuse unconditionally
    # — there is no flag to override this. The correct workflow is: reconnect
    # via console/VNC, then re-run.
    if [ -n "${SSH_CONNECTION:-}" ]; then
      err "Direct-spawn fallback would kill sshd — but you appear to be running over SSH:"
      err "  SSH_CONNECTION=$SSH_CONNECTION"
      err "  Killing all sshd processes would drop your own session."
      err "  Refusing. Reconnect via console/VNC, then re-run the script."
      audit_log "DIRECT_SPAWN_REFUSED" "SSH_CONNECTION=$SSH_CONNECTION"
      return 1
    fi
    # [v4.7.7 FIX-HIGH] Even without SSH_CONNECTION, running in a chroot
    # WITHOUT a separate PID namespace means `pkill -x sshd` reaches the
    # HOST's sshd processes — including any SSH sessions terminating to the
    # host. This is exactly the "operator opened console, then chroot
    # /mnt/target, then ran script" scenario. Refuse.
    if in_chroot_or_unknown; then
      err "Direct-spawn fallback would run pkill -x sshd, but this process appears to be"
      err "  in a chroot (or environment where /proc is missing). pkill would target the"
      err "  HOST's sshd (different PID namespace not detected). Refusing to avoid mass"
      err "  SSH disconnect on the host. Run from a proper container/VM or skip --delay-restart."
      audit_log "DIRECT_SPAWN_REFUSED" "reason=chroot_or_no_proc"
      return 1
    fi
    info "No init system available — performing direct sshd spawn"
    audit_log "DIRECT_SPAWN" "config=$SSH_CONF"
    # Validate the file before killing the live instance — if syntax is bad
    # we'd otherwise lock ourselves out.
    if ! sshd -t -f "$SSH_CONF" >>"$LOG_FILE" 2>&1; then
      err "Direct-spawn: sshd -t failed against $SSH_CONF"
      return 1
    fi
    # Try graceful first.
    pkill -TERM -x sshd >>"$LOG_FILE" 2>&1 || true
    # Brief settle.
    sleep 1
    # If sshd is still around, escalate.
    pkill -KILL -x sshd >>"$LOG_FILE" 2>&1 || true
    # Re-launch (daemon mode by default).
    if sshd -f "$SSH_CONF" >>"$LOG_FILE" 2>&1; then
      return 0
    fi
    res=$?
  fi

  return "$res"
}

# ---------------- Robust Rollback ----------------
ROLLBACK_DIR="$TMP_DIR/rollback"

update_state() {
  phase="$1"
  details="${2:-}"
  {
    echo "PHASE=$phase"
    echo "TIMESTAMP=$(date +%s)"
    echo "USER=${TARGET_USER:-unknown}"
    echo "PORT=${SSH_PORT:-22}"
    echo "KEY_OK=${KEY_OK:-n}"
    echo "DETAILS=$details"
  } > "$STATE_FILE" 2>/dev/null || true
  chmod 600 "$STATE_FILE" 2>/dev/null || true
}

parse_state_value() {
  key="$1"
  file="$2"
  if [ -f "$file" ] && [ -r "$file" ]; then
    sed -n "s/^${key}=//p" "$file" 2>/dev/null | head -n 1 | tr -d '\r'
  fi
}

check_previous_state() {
  if [ -f "$STATE_FILE" ]; then
    state_owner=""
    if stat -c "%u" "$STATE_FILE" >/dev/null 2>&1; then
      state_owner=$(stat -c "%u" "$STATE_FILE" 2>/dev/null)
    else
      state_owner=$(ls -ln "$STATE_FILE" 2>/dev/null | awk '{print $3}')
    fi
    
    current_uid=$(id -u)
    if [ "$state_owner" != "$current_uid" ] 2>/dev/null; then
      warn "State file owned by different user, ignoring"
      rm -f "$STATE_FILE" 2>/dev/null || true
      return 0
    fi
    
    warn "$(msg WARN_RESUME)"

    # [v4.7.0] Surface previous phase in the warning instead of just discarding it
    prev_phase=$(parse_state_value "PHASE" "$STATE_FILE")
    prev_user=$(parse_state_value "USER" "$STATE_FILE")
    prev_port=$(parse_state_value "PORT" "$STATE_FILE")
    [ -n "$prev_phase" ] && warn "  - previous phase: $prev_phase (user=$prev_user port=$prev_port)"

    # [v4.7.6 FIX-HIGH-N2] If a previous run crashed mid-way, its artifact
    # mirror in RUNTIME_DIR will be non-empty. Surface the artifacts so the
    # operator knows what mutations are stranded.
    prev_mirror="$RUNTIME_DIR/last-artifacts-$(id -u)"
    if [ -s "$prev_mirror" ]; then
      warn "  ⚠  Previous run left STRANDED mutations the new run cannot roll back:"
      __stranded_count=0
      while IFS= read -r __fact; do
        if [ -n "$__fact" ]; then
          warn "      - $__fact"
          __stranded_count=$((__stranded_count + 1))
        fi
      done < "$prev_mirror"
      warn "      Manual cleanup may be required (delete users / sudoers / firewall rules)."
      # [v4.7.8 FIX-MED W8-1] Audit-log the stranded state so SIEM / scripted
      # cron `--yes` runs don't silently accumulate detected-but-ignored
      # mutations. The detailed list is in $LOG_FILE; the audit entry just
      # records the count so an alert can fire.
      audit_log "STRANDED_MUTATIONS_DETECTED" "count=$__stranded_count mirror=$prev_mirror"
      unset __stranded_count __fact
    fi

    if [ "$AUTO_CONFIRM" != "y" ]; then
      printf "%s" "$(msg ASK_RESUME)"
      read -r continue_resume
      if [ "${continue_resume:-n}" != "y" ]; then
        rm -f "$STATE_FILE" 2>/dev/null || true
        exit 1
      fi
    fi

    [ -n "$prev_user" ] && [ -z "$ARG_USER" ] && TARGET_USER="$prev_user"
    [ -n "$prev_port" ] && [ -z "$ARG_PORT" ] && SSH_PORT="$prev_port"
  fi
}

cleanup_state() {
  rm -f "$STATE_FILE" 2>/dev/null || true
  # [v4.7.6 FIX-HIGH-N2] Clear the artifact mirror on success; the prev_mirror
  # detection above only fires when a previous run left a NON-EMPTY mirror.
  [ -n "${ARTIFACT_MIRROR:-}" ] && rm -f "$ARTIFACT_MIRROR" 2>/dev/null || true
}

cleanup_locks() {
  if [ -n "${LOCK_DIR:-}" ] && [ -d "$LOCK_DIR" ]; then
    rm -rf "$LOCK_DIR" 2>/dev/null || true
  fi
  # [v4.7.6 FIX-HIGH-N1] Release script-level mutex on every exit path.
  if [ -n "${SCRIPT_LOCK_DIR:-}" ] && [ -d "$SCRIPT_LOCK_DIR" ]; then
    rm -rf "$SCRIPT_LOCK_DIR" 2>/dev/null || true
  fi
}

# [v4.7.0 / v4.7.6] Artifact tracking. Each line in $ROLLBACK_DIR/artifacts
# is a fact the rollback handler can undo. Append-only, line-oriented,
# parsed in reverse.
# [v4.7.6 FIX-HIGH-N2] Also mirror appends into $RUNTIME_DIR/last-artifacts-UID
# so a script killed by SIGKILL / OOM / power loss can be recovered by the
# next run (TMP_DIR is per-mktemp and lost on hard-kill; RUNTIME_DIR survives).
ARTIFACT_FILE=""
ARTIFACT_MIRROR=""

artifact_track() {
  fact="$1"
  if [ -n "$ARTIFACT_FILE" ]; then
    printf '%s\n' "$fact" >> "$ARTIFACT_FILE" 2>/dev/null || true
  fi
  if [ -n "$ARTIFACT_MIRROR" ]; then
    printf '%s\n' "$fact" >> "$ARTIFACT_MIRROR" 2>/dev/null || true
  fi
}

# Reverse a file line-by-line in pure POSIX awk (no `tac` dependency).
__reverse_lines() {
  awk '{ a[NR] = $0 } END { for (i = NR; i >= 1; i--) print a[i] }' "$1" 2>/dev/null
}

rollback_handler() {
  RET=$?
  # [v4.7.0] Disarm signals immediately so a SIGINT mid-rollback can't re-enter.
  trap '' INT TERM HUP
  trap - EXIT

  if [ "$RET" -ne 0 ]; then
    warn ""
    warn "$(msg RB_START)"

    # 1. Undo recorded artifacts in REVERSE chronological order.
    #    [v4.7.1 FIX-M4] `|| [ -n "$fact" ]` ensures the loop also processes
    #    the LAST line even if a torn write (disk full) left it without LF.
    if [ -n "$ARTIFACT_FILE" ] && [ -f "$ARTIFACT_FILE" ]; then
      __reverse_lines "$ARTIFACT_FILE" | while IFS= read -r fact || [ -n "$fact" ]; do
        case "$fact" in
          USER_CREATED=*)
            u="${fact#USER_CREATED=}"
            if id "$u" >/dev/null 2>&1; then
              warn "  - removing user $u (and home dir)"
              # [v4.7.1 FIX-M5] Kill any processes owned by the user first,
              # otherwise userdel refuses to remove "user is currently used".
              if command -v pkill >/dev/null 2>&1; then
                pkill -KILL -u "$u" >>"$LOG_FILE" 2>&1 || true
                sleep 1
              fi
              userdel_ok=0
              if command -v userdel >/dev/null 2>&1; then
                userdel -r "$u" >>"$LOG_FILE" 2>&1 && userdel_ok=1 || userdel "$u" >>"$LOG_FILE" 2>&1 && userdel_ok=1
              elif command -v deluser >/dev/null 2>&1; then
                deluser --remove-home "$u" >>"$LOG_FILE" 2>&1 && userdel_ok=1 || deluser "$u" >>"$LOG_FILE" 2>&1 && userdel_ok=1
              fi
              if [ "$userdel_ok" != "1" ]; then
                audit_log "USER_REMOVE_FAILED" "Rollback could not remove user $u"
                err "  - userdel failed for $u (check $LOG_FILE)"
              fi
            fi
            ;;
          SUDOERS_FILE=*)
            # [v4.7.6 FIX-MED-N5] Verify rm actually removed the file. On
            # read-only /etc the rm silently fails; a stale sudoers entry
            # plus a deleted user creates a "passwordless sudo for any
            # future re-created user with the same name" privilege primitive.
            f="${fact#SUDOERS_FILE=}"
            if [ -f "$f" ]; then
              warn "  - removing $f"
              rm -f "$f" 2>/dev/null || true
              if [ -f "$f" ]; then
                err "  - FAILED to remove $f (read-only /etc?)"
                audit_log "ROLLBACK_RM_FAILED" "$f"
                rollback_clean=0
              fi
            fi
            ;;
          SYSTEMD_OVERRIDE=*)
            f="${fact#SYSTEMD_OVERRIDE=}"
            if [ -f "$f" ]; then
              warn "  - removing $f"
              rm -f "$f" 2>/dev/null || true
              if [ -f "$f" ]; then
                err "  - FAILED to remove $f"
                audit_log "ROLLBACK_RM_FAILED" "$f"
                rollback_clean=0
              fi
            fi
            command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1 || true
            ;;
          PROFILE_D_BANNER=*)
            f="${fact#PROFILE_D_BANNER=}"
            if [ -f "$f" ]; then
              warn "  - removing $f"
              rm -f "$f" 2>/dev/null || true
              if [ -f "$f" ]; then
                err "  - FAILED to remove $f"
                audit_log "ROLLBACK_RM_FAILED" "$f"
                rollback_clean=0
              fi
            fi
            ;;
          FIREWALL_PORT=*)
            # [v4.7.1 FIX-H2] Format is "backend:port" (e.g. "ufw:2222").
            # Backwards-compatible: if a pre-v4.7.1 artifact file has just the
            # port number, treat it as "iptables:port" (most likely).
            spec="${fact#FIREWALL_PORT=}"
            case "$spec" in
              *:*) fw_backend="${spec%%:*}"; fw_p="${spec#*:}" ;;
              *)   fw_backend="iptables";    fw_p="$spec" ;;
            esac
            warn "  - removing firewall rule (${fw_backend}) for tcp/$fw_p"
            case "$fw_backend" in
              ufw)
                command -v ufw >/dev/null 2>&1 && ufw delete allow "${fw_p}/tcp" >>"$LOG_FILE" 2>&1 || true
                ;;
              firewalld)
                if command -v firewall-cmd >/dev/null 2>&1; then
                  firewall-cmd --permanent --remove-port="${fw_p}/tcp" >>"$LOG_FILE" 2>&1 || true
                  firewall-cmd --reload >>"$LOG_FILE" 2>&1 || true
                fi
                ;;
              iptables)
                command -v iptables >/dev/null 2>&1 && iptables -D INPUT -p tcp --dport "$fw_p" -j ACCEPT >>"$LOG_FILE" 2>&1 || true
                ;;
            esac
            # IPv6 companion — try to remove if it exists; harmless if not.
            command -v ip6tables >/dev/null 2>&1 && ip6tables -D INPUT -p tcp --dport "$fw_p" -j ACCEPT >>"$LOG_FILE" 2>&1 || true
            ;;
          SELINUX_PORT=*)
            # [v4.7.5] Safe to delete: artifact_track for SELINUX_PORT only
            # fires when handle_selinux ADDED or MODIFIED (i.e. this run owns
            # the label). The NOOP path no longer tracks, so rollback cannot
            # delete a sysadmin-installed label by accident.
            p="${fact#SELINUX_PORT=}"
            if command -v semanage >/dev/null 2>&1; then
              warn "  - removing SELinux port label for $p"
              semanage port -d -t ssh_port_t -p tcp "$p" >>"$LOG_FILE" 2>&1 || true
            fi
            ;;
          BBR_SYSCTL=*)
            f="${fact#BBR_SYSCTL=}"
            [ -f "$f" ] || continue
            warn "  - reverting BBR sysctl lines from $f"
            tmpf="${f}.rb.$$"
            grep -vE '^(net\.core\.default_qdisc=fq|net\.ipv4\.tcp_congestion_control=bbr)$' "$f" > "$tmpf" 2>/dev/null && mv "$tmpf" "$f" 2>/dev/null || rm -f "$tmpf" 2>/dev/null
            ;;
          MOTD_BAK=*)
            # [v4.7.1 FIX-R3 / v4.7.6 FIX-MED-N6] Restore /etc/motd from .bak.
            # If .bak is missing (rare, e.g. it was manually removed), motd
            # stays in its modified state — surface this as a non-clean
            # rollback so the operator knows to manually clean up.
            f="${fact#MOTD_BAK=}"
            if [ -f "${f}.bak" ]; then
              warn "  - restoring $f from ${f}.bak"
              if ! mv "${f}.bak" "$f" 2>/dev/null; then
                err "    failed to restore motd from ${f}.bak"
                audit_log "ROLLBACK_MOTD_FAILED" "$f"
                rollback_clean=0
              fi
            else
              err "  - MOTD .bak missing; $f stays in modified state"
              audit_log "ROLLBACK_MOTD_BAK_MISSING" "$f"
              rollback_clean=0
            fi
            ;;
        esac
      done
    fi

    # 2. [v4.7.1 FIX-R2] Rename `.bak_server_init` files BACK to their originals.
    #    Previously these were rm -f'd, which permanently lost user data when
    #    the snapshot directory was empty or partial. The original drop-in
    #    content lives in this renamed file — restore it by renaming back.
    if [ -d "$SSH_CONF_D" ]; then
      for f in "$SSH_CONF_D"/*.bak_server_init; do
        [ -f "$f" ] || continue
        orig="${f%.bak_server_init}"
        warn "  - restoring renamed drop-in: $f → $orig"
        # If the snapshot has a fresher copy, prefer it; otherwise this rename
        # is the only source of truth.
        if [ -f "$ROLLBACK_DIR/sshd_config.d/$(basename "$orig")" ]; then
          rm -f "$f" 2>/dev/null || true
        else
          mv "$f" "$orig" 2>/dev/null || warn "    failed to rename"
        fi
      done
    fi

    # 3. Restore /etc/ssh/sshd_config.d/* — drop any files we ADDED during the
    #    run (not present in snapshot), then re-populate from snapshot.
    if [ -d "$ROLLBACK_DIR/sshd_config.d" ] && [ -d "$SSH_CONF_D" ]; then
      for f in "$SSH_CONF_D"/*; do
        [ -f "$f" ] || continue
        base=$(basename "$f")
        case "$base" in
          *.bak_server_init) continue ;;  # already handled in stage 2
        esac
        # Only delete if NOT present in the snapshot.
        if [ ! -f "$ROLLBACK_DIR/sshd_config.d/$base" ]; then
          rm -f "$f" 2>/dev/null || true
        fi
      done
      for f in "$ROLLBACK_DIR/sshd_config.d"/*; do
        [ -f "$f" ] || continue
        cp -p "$f" "$SSH_CONF_D"/ 2>/dev/null || warn "  - failed to restore $f"
      done
    fi

    # 4. Restore the main sshd_config from snapshot.
    if [ -f "$ROLLBACK_DIR/sshd_config" ]; then
      if ! cp -p "$ROLLBACK_DIR/sshd_config" "$SSH_CONF" 2>/dev/null; then
        err "  - FAILED to restore $SSH_CONF from snapshot"
      fi
      chmod 600 "$SSH_CONF" 2>/dev/null || true
    fi

    # 5. Restore iptables (now actually used — v4.6.x had captured but never applied).
    if [ -f "$ROLLBACK_DIR/iptables.backup" ] && command -v iptables-restore >/dev/null 2>&1; then
      # [v4.7.1 FIX-M6] iptables-restore replaces the entire ruleset with the
      # snapshot. Rules added by OTHER services since setup_rollback (e.g.
      # fail2ban triggers) will be wiped. Warn loudly.
      warn "  - iptables-restore: replacing live ruleset with snapshot taken at script start"
      warn "    (rules added by other services since then will be lost)"
      iptables-restore < "$ROLLBACK_DIR/iptables.backup" 2>>"$LOG_FILE" || warn "  - iptables-restore failed"
    fi

    # 6. Validate restored config & relaunch sshd. If either fails we MUST shout.
    #    [v4.7.2 FIX] Only relaunch sshd when the restored config passes
    #    `sshd -t`. Previously we restarted regardless, which could push a
    #    broken config to the live daemon (worst-case: sshd crashes and the
    #    machine is unreachable). When validation fails, we skip the restart
    #    so the LIVE sshd keeps running its current (pre-rollback) in-memory
    #    config — buying the operator time to reach VNC/console.
    rollback_clean=1
    config_ok=1
    if command -v sshd >/dev/null 2>&1; then
      if ! sshd -t -f "$SSH_CONF" 2>>"$LOG_FILE"; then
        rollback_clean=0
        config_ok=0
        err "  - restored sshd_config failed sshd -t — NOT restarting sshd to avoid pushing a broken config"
      fi
    fi
    if [ "$config_ok" = "1" ]; then
      # [v4.7.1 FIX-H4] Force-restart so --delay-restart runs still relaunch
      # the daemon during rollback.
      if ! restart_sshd force >/dev/null 2>&1; then
        rollback_clean=0
        err "  - restart_sshd failed during rollback"
      fi
    fi

    if [ "$rollback_clean" = "1" ]; then
      ok "$(msg RB_DONE)"
    else
      err "================================================================"
      err " ⚠  ROLLBACK COULD NOT FULLY RESTORE THE SYSTEM."
      err " ⚠  Open a VNC/console session and manually verify:"
      err "      - $SSH_CONF syntax (sshd -t)"
      err "      - sshd is listening on port 22"
      err "      - $LOG_FILE for the failure trail"
      err "================================================================"
    fi
    # [v4.7.3 FIX-H5] After a rollback, the LAST_APPLIED_FILE may point at a
    # firewall rule that no longer exists (we just removed it). Clear it so
    # the next run starts from a clean state.
    rm -f "$LAST_APPLIED_FILE" 2>/dev/null || true
    audit_log "ROLLBACK" "rc=$RET clean=$rollback_clean"
  else
    rm -rf "$TMP_DIR" 2>/dev/null || true
  fi

  cleanup_locks
  exit "$RET"
}

setup_rollback() {
  mkdir -p "$ROLLBACK_DIR" 2>/dev/null || true
  chmod 700 "$ROLLBACK_DIR" 2>/dev/null || true

  ARTIFACT_FILE="$ROLLBACK_DIR/artifacts"
  : > "$ARTIFACT_FILE" 2>/dev/null || true
  chmod 600 "$ARTIFACT_FILE" 2>/dev/null || true

  # [v4.7.6 FIX-HIGH-N2] Also persist the artifact file path AND mirror its
  # content into RUNTIME_DIR (which survives across script invocations,
  # unlike TMP_DIR which is per-mktemp). If this run is killed by SIGKILL /
  # OOM / power loss, the next script invocation can find the mirrored
  # artifact list and offer recovery. The mirror is updated by artifact_track
  # on every append.
  # [v4.7.6 FIX-followup] Order matters: assign the path FIRST, then let
  # check_previous_state read any orphaned content from a prior crashed run,
  # THEN truncate for our run. The earlier v4.7.6 draft truncated BEFORE
  # check_previous_state, making the orphan-surface logic dead code.
  ARTIFACT_MIRROR="$RUNTIME_DIR/last-artifacts-$(id -u)"

  check_previous_state

  : > "$ARTIFACT_MIRROR" 2>/dev/null || true
  chmod 600 "$ARTIFACT_MIRROR" 2>/dev/null || true

  update_state "setup" "Init"

  # [v4.7.7 FIX-MED] Verify the snapshot cp actually produced a non-empty
  # file. Previously a silent cp failure (ENOSPC, NFS hiccup, ENOTDIR) would
  # leave a 0-byte snapshot; later rollback would cp it back over the live
  # /etc/ssh/sshd_config, blanking it. sshd refuses to start with an empty
  # config → operator locked out. Refuse to proceed when the snapshot is
  # missing or empty.
  if [ -f "$SSH_CONF" ]; then
    if ! cp -p "$SSH_CONF" "$ROLLBACK_DIR/sshd_config" 2>>"$LOG_FILE"; then
      die "setup_rollback: cp $SSH_CONF → $ROLLBACK_DIR/sshd_config FAILED (disk full?). Refusing to proceed without a rollback snapshot."
    fi
    if [ ! -s "$ROLLBACK_DIR/sshd_config" ]; then
      die "setup_rollback: snapshot of $SSH_CONF is empty after cp (likely ENOSPC mid-write). Refusing to proceed."
    fi
  fi
  chmod 600 "$ROLLBACK_DIR/sshd_config" 2>/dev/null || true
  if [ -d "$SSH_CONF_D" ]; then
    mkdir -p "$ROLLBACK_DIR/sshd_config.d" 2>/dev/null || true
    chmod 700 "$ROLLBACK_DIR/sshd_config.d" 2>/dev/null || true
    for f in "$SSH_CONF_D"/*; do
      [ -f "$f" ] || continue
      # [v4.7.3 FIX-H6] Skip .bak_server_init files when snapshotting —
      # they're already-renamed originals from a prior crashed run and
      # capturing them would let stage-3 of rollback restore stale content.
      case "$f" in
        *.bak_server_init|*.bak_server_init.[0-9]*) continue ;;
      esac
      cp -p "$f" "$ROLLBACK_DIR/sshd_config.d/" 2>/dev/null || true
    done
  fi

  if command -v iptables-save >/dev/null 2>&1; then
    iptables-save > "$ROLLBACK_DIR/iptables.backup" 2>/dev/null || true
    chmod 600 "$ROLLBACK_DIR/iptables.backup" 2>/dev/null || true
  fi

  # [v4.7.0] Explicit per-signal handling. EXIT trap fires unconditionally; the
  # signal traps just `exit` with the standard 128+N code so EXIT sees a real
  # non-zero $? (dash sets $? = 0 after a bare signal otherwise).
  trap 'rollback_handler' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
}

# ---------------- Persistent Backup ----------------
# [SEC-FIX] Fixed cleanup_old_backups awk logic bug
cleanup_old_backups() {
  keep_count=10
  if [ -d "$BACKUP_REPO" ]; then
    backup_list=$(ls -dt "$BACKUP_REPO"/*/ 2>/dev/null) || return 0
    # [v4.7.3 FIX-MED] Use printf+wc instead of `grep -c . || echo 0`.
    # Previous form produced "0\n0" on empty input (grep -c outputs 0 AND
    # exits 1 → trailing `|| echo 0` appended a second 0), breaking the
    # numeric `-gt` compare.
    if [ -z "$backup_list" ]; then
      count=0
    else
      count=$(printf '%s\n' "$backup_list" | grep -c . 2>/dev/null)
      [ -z "$count" ] && count=0
    fi
    if [ "$count" -gt "$keep_count" ] 2>/dev/null; then
      to_rm=$((count - keep_count))
      info "$(msg INFO_CLEANING_BACKUPS) $to_rm $(msg INFO_OLD_BACKUPS)"
      # [SEC-FIX] Use tail -n to get oldest backups (last in sorted list)
      echo "$backup_list" | tail -n "$to_rm" | while IFS= read -r d; do
        [ -n "$d" ] && [ -d "$d" ] && rm -rf "$d" 2>/dev/null || true
      done
    fi
  fi
}

backup_config_persistent() {
  # [v4.7.0] All file creation inside this function happens with umask 077 so
  # backup.info / restore.sh / checksums.sha256 are 0600/0700 instead of 0644.
  __saved_umask=$(umask)
  umask 077

  timestamp=$(date +%Y%m%d_%H%M%S)
  if command -v date >/dev/null 2>&1 && date --version 2>&1 | grep -q GNU; then
    timestamp=$(date +%Y%m%d_%H%M%S%N 2>/dev/null || echo "$timestamp")
  fi

  backup_dir="$BACKUP_REPO/$timestamp"

  if ! mkdir -p "$BACKUP_REPO" 2>/dev/null; then
    warn "$(msg ERR_BACKUP_DIR) $BACKUP_REPO"
    # [v4.7.0 / HIGH] /tmp fallback only succeeds if the path doesn't already
    # exist with the wrong owner (defeats predictable-path squatting).
    alt="/tmp/server-init-backups"
    if [ -e "$alt" ] && [ ! -d "$alt" ]; then
      warn "$(msg ERR_BACKUP_DIR_ALT) ($alt exists and is not a directory)"
      umask "$__saved_umask"
      return 1
    fi
    if [ -d "$alt" ]; then
      owner=$(stat -c "%u" "$alt" 2>/dev/null || ls -ld "$alt" 2>/dev/null | awk '{print $3}')
      if [ -n "$owner" ] && [ "$owner" != "0" ] && [ "$owner" != "root" ]; then
        warn "$(msg ERR_BACKUP_DIR_ALT) (refusing to use $alt — owned by $owner)"
        umask "$__saved_umask"
        return 1
      fi
    fi
    BACKUP_REPO="$alt"
    backup_dir="$BACKUP_REPO/$timestamp"
    if ! mkdir -p "$BACKUP_REPO" 2>/dev/null; then
      warn "$(msg ERR_BACKUP_DIR_ALT)"
      umask "$__saved_umask"
      return 1
    fi
  fi

  chmod 700 "$BACKUP_REPO" 2>/dev/null || true

  if ! mkdir -p "$backup_dir" 2>/dev/null; then
    warn "$(msg ERR_BACKUP_SUBDIR) $backup_dir"
    umask "$__saved_umask"
    return 1
  fi

  chmod 700 "$backup_dir" 2>/dev/null || true

  if [ -f "$SSH_CONF" ]; then
    # [v4.7.7 FIX-MED] Don't silently swallow cp failure — the persistent
    # backup is what `restore.sh` uses, so an incomplete cp would mean
    # operator's manual recovery gets a 0-byte sshd_config and bricks
    # the box harder. Failing the backup here just skips this persistent
    # snapshot (script continues — backup is opportunistic, not load-bearing).
    if ! cp -p "$SSH_CONF" "$backup_dir/sshd_config" 2>>"$LOG_FILE"; then
      warn "Persistent backup cp failed (disk full?); restore.sh from this backup will NOT work"
      rm -f "$backup_dir/sshd_config" 2>/dev/null || true
    elif [ ! -s "$backup_dir/sshd_config" ]; then
      warn "Persistent backup snapshot is empty (truncated mid-write); removing"
      rm -f "$backup_dir/sshd_config" 2>/dev/null || true
    else
      chmod 600 "$backup_dir/sshd_config" 2>/dev/null || true
    fi
  fi

  if [ -d "$SSH_CONF_D" ]; then
    mkdir -p "$backup_dir/sshd_config.d" 2>/dev/null && chmod 700 "$backup_dir/sshd_config.d" 2>/dev/null || true
    for f in "$SSH_CONF_D"/*; do
      [ -f "$f" ] || continue
      cp -p "$f" "$backup_dir/sshd_config.d/" 2>/dev/null || true
    done
  fi

  {
    echo "=== Server Init Backup ==="
    echo "Time: $(date)"
    echo "Version: 4.7.8"
    echo "User: ${TARGET_USER:-unknown}"
    echo "Port: ${SSH_PORT:-unknown}"
    echo "OpenSSH: ${OPENSSH_VER_MAJOR}.${OPENSSH_VER_MINOR}"
    echo "--- System ---"
    uname -a 2>/dev/null || true
    echo ""
    echo "Note: restore.sh restores ONLY $SSH_CONF and sshd_config.d/."
    echo "User accounts, sudoers files, systemd overrides, firewall rules,"
    echo "SELinux port labels and BBR sysctl entries created by the run are"
    echo "NOT undone by restore.sh — use runtime auto-rollback instead."
  } > "$backup_dir/backup.info" 2>/dev/null || true
  chmod 600 "$backup_dir/backup.info" 2>/dev/null || true

  # [v4.7.0 / HIGH] restore.sh now verifies checksums before applying.
  cat > "$backup_dir/restore.sh" <<'EOF'
#!/bin/sh
# Auto-generated by linux-ssh-init-sh v4.7.8
# Restores /etc/ssh/sshd_config (and sshd_config.d/) from this backup directory
# after verifying that the files match checksums.sha256.
set -eu
BACKUP_DIR=$(cd "$(dirname "$0")" && pwd)
SSH_CONFIG="/etc/ssh/sshd_config"
SSH_CONFIG_D="/etc/ssh/sshd_config.d"

if [ "$(id -u)" -ne 0 ]; then
  echo "Must be run as root" >&2
  exit 1
fi

echo "[restore] Verifying integrity..."
# [v4.7.3 FIX-MED] Default to STRICT (refuse missing checksum). An attacker
# who can write to the backup dir could otherwise delete checksums.sha256 to
# neutralize verification. Set FORCE=1 in the environment to override (e.g.
# when restoring a backup created by an older version that lacked sha256s).
if [ ! -f "$BACKUP_DIR/checksums.sha256" ]; then
  if [ "${FORCE:-0}" != "1" ]; then
    echo "[restore] REFUSING: checksums.sha256 missing. Re-run with FORCE=1 to bypass." >&2
    exit 5
  fi
  echo "[restore] WARNING: FORCE=1 — proceeding without checksum verification." >&2
elif ! command -v sha256sum >/dev/null 2>&1; then
  if [ "${FORCE:-0}" != "1" ]; then
    echo "[restore] REFUSING: sha256sum not available. Re-run with FORCE=1 to bypass." >&2
    exit 6
  fi
  echo "[restore] WARNING: FORCE=1 — sha256sum unavailable, skipping verification." >&2
else
  ( cd "$BACKUP_DIR" && sha256sum -c checksums.sha256 ) || {
    echo "[restore] CHECKSUM MISMATCH — refusing to restore tampered backup." >&2
    exit 2
  }
fi

if [ ! -f "$BACKUP_DIR/sshd_config" ]; then
  echo "[restore] No sshd_config snapshot found." >&2
  exit 3
fi

ts=$(date +%s)
cp -p "$SSH_CONFIG" "$SSH_CONFIG.bak-$ts" 2>/dev/null || true
cp -p "$BACKUP_DIR/sshd_config" "$SSH_CONFIG"
chmod 600 "$SSH_CONFIG" 2>/dev/null || true

if [ -d "$BACKUP_DIR/sshd_config.d" ] && [ -d "$SSH_CONFIG_D" ]; then
  for f in "$BACKUP_DIR/sshd_config.d"/*; do
    [ -f "$f" ] || continue
    cp -p "$f" "$SSH_CONFIG_D/" 2>/dev/null || true
  done
fi

echo "[restore] Validating restored config..."
if command -v sshd >/dev/null 2>&1; then
  sshd -t || { echo "[restore] sshd -t failed against restored config!" >&2; exit 4; }
fi

echo "[restore] Restarting sshd..."
systemctl restart sshd 2>/dev/null || service sshd restart 2>/dev/null || /etc/init.d/sshd restart 2>/dev/null || true
echo "[restore] Done. Test connectivity in a NEW terminal before closing this one."
EOF
  chmod 700 "$backup_dir/restore.sh" 2>/dev/null || true

  # Generate checksums LAST so they cover every other file in the dir.
  (
    cd "$backup_dir" || exit 0
    # exclude any pre-existing checksums file from being self-referential
    rm -f checksums.sha256 2>/dev/null
    # [v4.7.1] xargs -r is GNU-only; BusyBox xargs lacks it. The input is
    # never empty in practice (backup.info + restore.sh always exist) so we
    # can drop the flag for portability.
    find . -maxdepth 2 -type f ! -name 'checksums.sha256' -print 2>/dev/null \
      | sed 's|^\./||' \
      | sort \
      | xargs sha256sum 2>/dev/null > checksums.sha256
    chmod 600 checksums.sha256 2>/dev/null || true
  ) || true

  umask "$__saved_umask"

  cleanup_old_backups
  info "$(msg INFO_BACKUP_CREATED) $backup_dir"
  return 0
}

# ---------------- BBR ----------------
enable_bbr() {
  command -v sysctl >/dev/null 2>&1 || return 0
  if ! sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q bbr; then
    warn "Kernel does not support BBR, skipping."
    return 0
  fi
  sysctl_conf="/etc/sysctl.conf"
  # [v4.7.4 FIX-LOW] Defense-in-depth: if /etc/sysctl.conf is a symlink, the
  # >> redirect would follow it. Refuse to append in that case (don't blindly
  # remove — sysctl.conf is sometimes legitimately a symlink to a packaged file).
  if [ -L "$sysctl_conf" ]; then
    warn "$sysctl_conf is a symlink — skipping BBR sysctl write (manual configuration required)"
    return 0
  fi
  added_any=0
  if ! grep -q '^net.core.default_qdisc=fq$' "$sysctl_conf" 2>/dev/null; then
    echo 'net.core.default_qdisc=fq' >> "$sysctl_conf"
    added_any=1
  fi
  if ! grep -q '^net.ipv4.tcp_congestion_control=bbr$' "$sysctl_conf" 2>/dev/null; then
    echo 'net.ipv4.tcp_congestion_control=bbr' >> "$sysctl_conf"
    added_any=1
  fi
  if [ "$added_any" = "1" ]; then
    artifact_track "BBR_SYSCTL=$sysctl_conf"
    audit_log "BBR_ENABLED" "appended to $sysctl_conf"
  fi
  sysctl -p >>"$LOG_FILE" 2>&1 || true
}

# ---------------- SSHD Helpers ----------------
ensure_ssh_server() {
  if [ -f "$SSH_CONF" ] && command -v sshd >/dev/null 2>&1; then
    return 0
  fi
  info "$(msg I_SSH_INSTALL)"
  case "$PM" in
    apk) install_pkg openssh openssh-server ;;
    *)   install_pkg openssh-server ;;
  esac

  if ! command -v sshd >/dev/null 2>&1; then
    die "$(msg ERR_MISSING_SSHD)"
  fi
  [ -f "$SSH_CONF" ] || die "OpenSSH Install Failed"
}

protect_sshd_service() {
  command -v systemctl >/dev/null 2>&1 || return 0
  info "$(msg SYS_PROT)"
  systemctl enable ssh sshd 2>/dev/null || true
  systemctl unmask ssh sshd 2>/dev/null || true

  override_dir="/etc/systemd/system/sshd.service.d"
  override_file="$override_dir/override.conf"

  # [v4.7.0 / MED] Refuse to follow a symlinked override dir (package compromise vector)
  if [ -L "$override_dir" ]; then
    warn "$override_dir is a symlink — skipping systemd override"
    return 0
  fi
  mkdir -p "$override_dir" 2>/dev/null || true
  chmod 755 "$override_dir" 2>/dev/null || true

  # [v4.7.4 FIX-LOW] Symlink defense (override_file path).
  unlink_if_symlink "$override_file"
  # Only write (and track) if file is new or content differs.
  desired_content='[Service]
Restart=on-failure
RestartSec=5s
OOMScoreAdjust=-500'
  if [ ! -f "$override_file" ] || ! printf '%s' "$desired_content" | cmp -s - "$override_file" 2>/dev/null; then
    printf '%s\n' "$desired_content" > "$override_file" 2>/dev/null || warn "failed to write $override_file"
    chmod 644 "$override_file" 2>/dev/null || true
    chown root:root "$override_file" 2>/dev/null || true
    artifact_track "SYSTEMD_OVERRIDE=$override_file"
    audit_log "SYSTEMD_OVERRIDE_WRITTEN" "$override_file"
  fi
  systemctl daemon-reload >>"$LOG_FILE" 2>&1 || true
}

detect_openssh_version() {
  OPENSSH_VER_MAJOR=0
  OPENSSH_VER_MINOR=0
  ver_str=""

  if command -v sshd >/dev/null 2>&1; then
    ver_str=$(sshd -V 2>&1 | sed -n 's/.*OpenSSH_\([0-9]*\)\.\([0-9]*\).*/\1.\2/p' | head -1)
  fi

  if [ -z "$ver_str" ] && command -v ssh >/dev/null 2>&1; then
    ver_str=$(ssh -V 2>&1 | sed -n 's/.*OpenSSH_\([0-9]*\)\.\([0-9]*\).*/\1.\2/p' | head -1)
  fi

  if [ -n "$ver_str" ]; then
    OPENSSH_VER_MAJOR=$(echo "$ver_str" | cut -d. -f1 2>/dev/null || echo 0)
    OPENSSH_VER_MINOR=$(echo "$ver_str" | cut -d. -f2 2>/dev/null || echo 0)
  fi

  case "$OPENSSH_VER_MAJOR" in
    ''|*[!0-9]*) OPENSSH_VER_MAJOR=7 ;;
  esac
  case "$OPENSSH_VER_MINOR" in
    ''|*[!0-9]*) OPENSSH_VER_MINOR=0 ;;
  esac
  [ "$OPENSSH_VER_MAJOR" -eq 0 ] 2>/dev/null && OPENSSH_VER_MAJOR=7
}

openssh_version_ge() {
  req_major="$1"
  req_minor="${2:-0}"

  [ "$OPENSSH_VER_MAJOR" -gt "$req_major" ] && return 0
  [ "$OPENSSH_VER_MAJOR" -eq "$req_major" ] && [ "$OPENSSH_VER_MINOR" -ge "$req_minor" ] && return 0
  return 1
}

# [SEC-FIX] Detect if sshd supports KbdInteractiveAuthentication
detect_kbd_interactive_support() {
  SUPPORTS_KBD_INTERACTIVE="n"
  if command -v sshd >/dev/null 2>&1; then
    if sshd -T 2>/dev/null | grep -qi '^kbdinteractiveauthentication'; then
      SUPPORTS_KBD_INTERACTIVE="y"
    fi
  fi
}

# ---------------- Firewall / SELinux ----------------

# [v4.7.3 FIX-H5 / v4.7.4 extended] Read last-applied state from disk and, if
# it records a DIFFERENT port than the one we're about to install, remove
# stale firewall AND SELinux state so a chain of `--port=X then --port=Y`
# runs doesn't leave cruft on every prior X.
remove_stale_firewall_port() {
  new_port="$1"
  [ -f "$LAST_APPLIED_FILE" ] || return 0

  # ---- Firewall stale-rule cleanup ----
  old_spec=$(awk -F= '$1=="FIREWALL"{print $2; exit}' "$LAST_APPLIED_FILE" 2>/dev/null)
  if [ -n "$old_spec" ]; then
    case "$old_spec" in
      *:*) old_backend="${old_spec%%:*}"; old_port="${old_spec#*:}" ;;
      *)   old_backend="iptables";        old_port="$old_spec" ;;
    esac
    case "$old_port" in ''|*[!0-9]*) old_port="" ;; esac
    if [ -n "$old_port" ] && [ "$old_port" != "$new_port" ] && [ "$old_port" != "22" ]; then
      warn "Cleaning stale firewall rule from previous run: tcp/$old_port (backend: $old_backend)"
      case "$old_backend" in
        ufw)       command -v ufw >/dev/null 2>&1 && ufw delete allow "${old_port}/tcp" >>"$LOG_FILE" 2>&1 || true ;;
        firewalld)
          if command -v firewall-cmd >/dev/null 2>&1; then
            firewall-cmd --permanent --remove-port="${old_port}/tcp" >>"$LOG_FILE" 2>&1 || true
            firewall-cmd --reload >>"$LOG_FILE" 2>&1 || true
          fi ;;
        iptables)  command -v iptables  >/dev/null 2>&1 && iptables  -D INPUT -p tcp --dport "$old_port" -j ACCEPT >>"$LOG_FILE" 2>&1 || true ;;
      esac
      command -v ip6tables >/dev/null 2>&1 && ip6tables -D INPUT -p tcp --dport "$old_port" -j ACCEPT >>"$LOG_FILE" 2>&1 || true
      audit_log "STALE_FIREWALL_REMOVED" "backend=$old_backend port=$old_port"
    fi
  fi

  # ---- [v4.7.4 / v4.7.5 FIX-MED-1] SELinux stale-label cleanup ----
  # Only delete a label that THIS script previously INSTALLED (SELINUX_OWNED=y).
  # A label recorded as NOOP (SELINUX_OWNED=n) belongs to the operator or
  # was set up out-of-band — deleting it would silently destroy unrelated
  # system state.
  old_se=$(awk -F= '$1=="SELINUX_PORT"{print $2; exit}'   "$LAST_APPLIED_FILE" 2>/dev/null)
  old_owned=$(awk -F= '$1=="SELINUX_OWNED"{print $2; exit}' "$LAST_APPLIED_FILE" 2>/dev/null)
  case "$old_se" in ''|*[!0-9]*) old_se="" ;; esac

  if [ -n "$old_se" ] && [ "$old_se" != "$new_port" ] && [ "$old_se" != "22" ]; then
    if [ "$old_owned" = "y" ]; then
      if command -v semanage >/dev/null 2>&1; then
        warn "Removing stale SELinux ssh_port_t label from previous run: tcp/$old_se"
        if semanage port -d -t ssh_port_t -p tcp "$old_se" >>"$LOG_FILE" 2>&1; then
          audit_log "STALE_SELINUX_REMOVED" "port=$old_se"
          # [v4.7.5 FIX-MED-2 / v4.7.6 FIX-MED] Strip SELINUX_PORT= and
          # SELINUX_OWNED= lines from the persisted file. If the script
          # crashes between here and the next record_last_applied call, the
          # file won't claim we still own a label that no longer exists.
          #
          # v4.7.6 fix: previous form `grep -v ... > tmp && mv || rm tmp`
          # broke when the file contained ONLY SELINUX_* lines — grep -v
          # produced no output, exited 1, the mv never fired, the rm cleaned
          # tmp, and the original file kept the stale lines. Use `|| true`
          # to mask grep's no-match exit code, then mv unconditionally.
          if [ -f "$LAST_APPLIED_FILE" ]; then
            __tmp_la="${LAST_APPLIED_FILE}.tmp.$$"
            grep -vE '^(SELINUX_PORT|SELINUX_OWNED)=' "$LAST_APPLIED_FILE" 2>/dev/null > "$__tmp_la" || true
            if mv "$__tmp_la" "$LAST_APPLIED_FILE" 2>/dev/null; then
              chmod 600 "$LAST_APPLIED_FILE" 2>/dev/null || true
            else
              rm -f "$__tmp_la" 2>/dev/null || true
            fi
            unset __tmp_la
          fi
        else
          audit_log "STALE_SELINUX_REMOVE_FAILED" "port=$old_se"
        fi
      else
        audit_log "STALE_SELINUX_SKIP" "port=$old_se reason=no_semanage"
        warn "Cannot remove stale SELinux label (semanage not installed): tcp/$old_se"
      fi
    else
      # Pre-existing label (SELINUX_OWNED=n). Don't delete; just note.
      audit_log "STALE_SELINUX_KEPT" "port=$old_se reason=not_owned_by_script"
    fi
  fi
}

# [v4.7.3 FIX-H5 / v4.7.4 / v4.7.5] Write the current state to
# LAST_APPLIED_FILE so the NEXT run can pick up where this one left off.
# Args:
#   $1 = port (validated digits)
#   $2 = firewall backend ("" if none)
#   $3 = "y" if THIS run's port is labeled ssh_port_t (NOOP or ADDED/MODIFIED)
#   $4 = "y" if THIS run actually INSTALLED/RETYPED the label (i.e. cleanup
#        on next run is allowed to `semanage port -d` it); "n" means the
#        label pre-existed independently (sysadmin-installed) and must be
#        preserved across port changes / rollbacks.
record_last_applied() {
  port="$1"; backend="$2"; selinux="${3:-n}"; owned="${4:-n}"
  mkdir -p "$(dirname "$LAST_APPLIED_FILE")" 2>/dev/null || return 0
  chmod 700 "$(dirname "$LAST_APPLIED_FILE")" 2>/dev/null || true
  # [v4.7.4 FIX-LOW] Symlink defense before writing.
  unlink_if_symlink "$LAST_APPLIED_FILE"

  # Preserve existing SELINUX_PORT/SELINUX_OWNED if caller didn't pass them.
  preserved_se=""
  preserved_owned=""
  if [ "$selinux" != "y" ] && [ -f "$LAST_APPLIED_FILE" ]; then
    preserved_se=$(awk -F= '$1=="SELINUX_PORT"{print $2; exit}' "$LAST_APPLIED_FILE" 2>/dev/null)
    preserved_owned=$(awk -F= '$1=="SELINUX_OWNED"{print $2; exit}' "$LAST_APPLIED_FILE" 2>/dev/null)
  fi

  # [v4.7.7 FIX-MED] Atomic write: previously a direct `> "$LAST_APPLIED_FILE"`
  # truncate-then-write left the file partial/empty on signal or ENOSPC mid-
  # write — the next run misinterpreted the orphaned state and either left a
  # stale firewall rule untouched or tried to `semanage port -d` a non-existent
  # label. Write to .tmp, then atomically mv.
  __la_tmp="${LAST_APPLIED_FILE}.tmp.$$"
  {
    [ -n "$backend" ] && printf 'FIREWALL=%s:%s\n' "$backend" "$port"
    printf 'PORT=%s\n' "$port"
    if [ "$selinux" = "y" ]; then
      printf 'SELINUX_PORT=%s\n' "$port"
      printf 'SELINUX_OWNED=%s\n' "$owned"
    elif [ -n "$preserved_se" ]; then
      printf 'SELINUX_PORT=%s\n' "$preserved_se"
      [ -n "$preserved_owned" ] && printf 'SELINUX_OWNED=%s\n' "$preserved_owned"
    fi
  } > "$__la_tmp" 2>/dev/null
  if [ -s "$__la_tmp" ]; then
    mv "$__la_tmp" "$LAST_APPLIED_FILE" 2>/dev/null || rm -f "$__la_tmp" 2>/dev/null
    chmod 600 "$LAST_APPLIED_FILE" 2>/dev/null || true
  else
    rm -f "$__la_tmp" 2>/dev/null || true
  fi
  unset __la_tmp
}

# [v4.7.1 FIX-H2] Tag the artifact with WHICH backend added the rule, so the
# rollback path only undoes that backend (instead of blindly trying all three
# and potentially deleting an unrelated rule that another tool installed).
allow_firewall_port() {
  p="$1"
  backend=""
  # [v4.7.8 FIX-MED W2-2] Differentiate "rule actually added" from "rule
  # already there" so idempotent re-runs don't pollute the audit log with
  # phantom FIREWALL_OPENED entries.
  rule_was_new="n"

  if command -v ufw >/dev/null 2>&1; then
    # ufw allow returns the same exit code whether new or pre-existing —
    # check via `ufw status` BEFORE adding.
    if ufw status 2>/dev/null | grep -Eq "^${p}/tcp[[:space:]]+ALLOW"; then
      backend="ufw"  # pre-existing — track for rollback symmetry but don't claim "OPENED"
    else
      ufw allow "${p}/tcp" >>"$LOG_FILE" 2>&1 && { backend="ufw"; rule_was_new="y"; } || true
    fi
  elif command -v firewall-cmd >/dev/null 2>&1; then
    if firewall-cmd --query-port="${p}/tcp" >/dev/null 2>&1; then
      backend="firewalld"  # pre-existing
    elif firewall-cmd --permanent --add-port="${p}/tcp" >>"$LOG_FILE" 2>&1; then
      firewall-cmd --reload >>"$LOG_FILE" 2>&1 || true
      backend="firewalld"; rule_was_new="y"
    fi
  elif command -v iptables >/dev/null 2>&1; then
    if iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null; then
      backend="iptables"  # pre-existing
    elif iptables -I INPUT -p tcp --dport "$p" -j ACCEPT 2>>"$LOG_FILE"; then
      backend="iptables"; rule_was_new="y"
    fi
  fi

  # IPv6 — not tracked separately. We treat it as a best-effort companion.
  if command -v ip6tables >/dev/null 2>&1; then
    if ip6tables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null; then
      :
    else
      ip6tables -I INPUT -p tcp --dport "$p" -j ACCEPT 2>>"$LOG_FILE" || true
    fi
  fi

  # [v4.7.8 FIX-MED W2-2] Only emit FIREWALL_OPENED audit + artifact_track
  # when we actually INSTALLED the rule. Pre-existing rules don't need
  # rollback (we didn't create them) and shouldn't show in the audit trail
  # as "opened by this run".
  if [ -n "$backend" ] && [ "$rule_was_new" = "y" ]; then
    artifact_track "FIREWALL_PORT=${backend}:${p}"
    audit_log "FIREWALL_OPENED" "backend=$backend port=$p"
    # [v4.7.3 FIX-H5] Persist so the next run can remove this rule if the
    # port changes. Only after success; rollback removes the artifact AND
    # rewrites/discards the persisted state via cleanup of the in-flight run.
    # [v4.7.5] At this point handle_selinux hasn't run yet, so the SELinux
    # state is whatever a previous run persisted (preserved automatically).
    # The second record_last_applied call below (after handle_selinux) is the
    # one that knows OWNED vs NOOP and persists the final state.
    record_last_applied "$p" "$backend" "n" "n"
  elif [ -n "$backend" ]; then
    audit_log "FIREWALL_NOOP" "backend=$backend port=$p reason=already_allowed"
    # Still update LAST_APPLIED_FILE so next run knows what backend we'd use
    # to clean it if the port changes.
    record_last_applied "$p" "$backend" "n" "n"
  fi

  if [ "$STRICT_MODE" = "y" ] && [ -z "$backend" ]; then
    case "$p" in
      22) ;;
      *)  warn "STRICT: could not confirm firewall rule for tcp/$p" ;;
    esac
  fi
}

handle_selinux() {
  port="$1"
  # [v4.7.6 FIX-CRIT] Initialize __selinux_done — without this, the
  # "all 3 semanage attempts failed" path (else-branch) doesn't set it,
  # then the `[ "$__selinux_done" = "y" ]` check below errors under
  # `set -u`, crashing the script and triggering rollback. This defeats
  # the non-strict graceful-degrade design (should warn + continue).
  __selinux_done="n"
  command -v getenforce >/dev/null 2>&1 || return 0
  getenforce 2>/dev/null | grep -qi "Enforcing" || return 0

  info "$(msg SELINUX_DET)"
  if ! command -v semanage >/dev/null 2>&1; then
    info "$(msg SELINUX_INS)"
    case "$PM" in
      yum) install_pkg_try policycoreutils-python-utils policycoreutils-python ;;
      apt) install_pkg_try policycoreutils python3-policycoreutils ;;
    esac
  fi
  if command -v semanage >/dev/null 2>&1; then
    # [v4.7.4 FIX] Check FIRST whether this port is ALREADY labeled as
    # ssh_port_t. If so, both `-a` (duplicate) and `-m` (no-op) succeed but
    # the previous code falsely warned "previous SELinux type was
    # overwritten" — there was nothing to overwrite. Now we no-op cleanly.
    if semanage port -l 2>/dev/null | awk -v p="$port" '
        $1=="ssh_port_t" {
          for (i=3; i<=NF; i++) {
            gsub(/,/, "", $i)
            if ($i == p) { found=1; exit }
          }
        }
        END { exit !found }
      '; then
      info "SELinux port $port already labeled ssh_port_t — no-op"
      audit_log "SELINUX_PORT_NOOP" "port=$port already_labeled"
      # [v4.7.5 FIX-MED-1] DO NOT artifact_track here. The label pre-existed
      # before this run (sysadmin-installed or set by a prior script run that
      # already persisted state). Tracking it would let rollback `semanage
      # port -d` a label we didn't create. The OWNERSHIP record lives in
      # LAST_APPLIED_FILE if a previous run actually installed it.
      __selinux_done="y"
    elif semanage port -a -t ssh_port_t -p tcp "$port" >>"$LOG_FILE" 2>&1; then
      artifact_track "SELINUX_PORT=$port"
      audit_log "SELINUX_PORT_ADDED" "port=$port type=ssh_port_t"
      ok "$(msg SELINUX_OK)"
      SELINUX_LABEL_OWNED_BY_RUN="y"
      __selinux_done="y"
    elif semanage port -m -t ssh_port_t -p tcp "$port" >>"$LOG_FILE" 2>&1; then
      # [v4.7.3 FIX-H7] `-m` modifies an EXISTING label that wasn't already
      # ssh_port_t (caught above) — some other service had this port (e.g.
      # http_port_t). Can't cleanly restore the original label on rollback.
      warn "SELinux port $port was MODIFIED (not added) — previous SELinux type was overwritten"
      warn "  If another service used this port label, restore it manually:"
      warn "  semanage port -d -t ssh_port_t -p tcp $port && semanage port -a -t <ORIG_TYPE> -p tcp $port"
      audit_log "SELINUX_PORT_MODIFIED" "port=$port (previous label overwritten, no rollback)"
      [ "$STRICT_MODE" = "y" ] && die "STRICT: refusing to overwrite SELinux port label that already exists"
      ok "$(msg SELINUX_OK)"
      # [v4.7.5] -m path: WE retyped the label, so we own it. Rollback can
      # safely `semanage port -d` (though it won't restore the original type).
      SELINUX_LABEL_OWNED_BY_RUN="y"
      __selinux_done="y"
    else
      warn "$(msg SELINUX_FAIL)"
      audit_log "SELINUX_PORT_FAIL" "port=$port"
      [ "$STRICT_MODE" = "y" ] && die "STRICT: SELinux port label add failed"
    fi
    # [v4.7.4 / v4.7.5] Export to caller so allow_firewall_port's
    # record_last_applied can persist SELinux state.
    # SELINUX_LABEL_APPLIED is the "should we record this port in
    # LAST_APPLIED_FILE" signal (true if NOOP, ADDED, or MODIFIED — anything
    # that means "this run's port is labeled ssh_port_t").
    # SELINUX_LABEL_OWNED_BY_RUN is the "may rollback delete it" signal —
    # only true when WE installed or retyped the label.
    [ "$__selinux_done" = "y" ] && SELINUX_LABEL_APPLIED="y"
  else
    warn "$(msg SELINUX_FAIL)"
  fi
}

# ---------------- Port Logic ----------------
is_hard_reserved() {
  case "$1" in
    53|80|443|3306)
      return 0 ;;
  esac
  return 1
}

is_k8s_nodeport() { [ "$1" -ge 30000 ] && [ "$1" -le 32767 ]; }

rand_u16() {
  if [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then
    od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' '
  elif command -v shuf >/dev/null 2>&1; then
    shuf -i 1024-65535 -n 1
  else
    echo $(( ( $(date +%s 2>/dev/null || echo 12345) + $$ ) % 65536 ))
  fi
}

ensure_port_tools() {
  # === [新增] 强制安装 nc (netcat) ===
  if ! command -v nc >/dev/null 2>&1; then
    echo "Installing missing dependency: netcat..."
    case "$PM" in
      # [v4.7.3 FIX-MED] Try multiple `nc` package names — varies by distro
      # (netcat-openbsd on Debian/Ubuntu/Alpine, nmap-ncat or nc on RHEL).
      apt) install_pkg_try netcat-openbsd netcat ncat ;;
      yum) install_pkg_try nmap-ncat nc netcat ;;
      apk) install_pkg_try netcat-openbsd ncat ;;
    esac
  fi
  # ==============================

  # 原有的 ss/netstat 检查保持不变
  command -v ss >/dev/null 2>&1 && return 0
  command -v netstat >/dev/null 2>&1 && return 0
  case "$PM" in
    apt) install_pkg_try iproute2 >/dev/null 2>&1 || true ;;
    yum) install_pkg_try iproute  >/dev/null 2>&1 || true ;;
    apk) install_pkg_try iproute2 iproute2-ss >/dev/null 2>&1 || true ;;
  esac
  install_pkg_try net-tools >/dev/null 2>&1 || true
}

is_port_free() {
  p="$1"

  if command -v ss >/dev/null 2>&1; then
    if ss -lnt 2>/dev/null | awk -v port="$p" '
      BEGIN { found = 0 }
      NR > 1 {
        n = split($4, parts, ":")
        if (parts[n] == port) { found = 1; exit }
      }
      END { exit !found }
    '; then
      return 1
    fi
    return 0
  fi

  if command -v netstat >/dev/null 2>&1; then
    if netstat -lnt 2>/dev/null | awk -v port="$p" '
      BEGIN { found = 0 }
      NR > 2 {
        n = split($4, parts, ":")
        if (parts[n] == port) { found = 1; exit }
      }
      END { exit !found }
    '; then
      return 1
    fi
    return 0
  fi

  return 1
}

pick_random_port() {
  ensure_port_tools
  i=0

  if ! mkdir -p "$LOCK_DIR" 2>/dev/null; then
    warn "$(msg ERR_LOCK_DIR) $LOCK_DIR"
    return 1
  fi
  chmod 700 "$LOCK_DIR" 2>/dev/null || warn "$(msg WARN_LOCK_DIR_PERM)"
  find "$LOCK_DIR" -name "port-*.lock" -mmin +5 -delete 2>/dev/null || true

  while [ "$i" -lt 100 ]; do
    r="$(rand_u16)"
    p=$(( 49152 + (r % (65535 - 49152)) ))
    lockfile="$LOCK_DIR/port-$p.lock"
    if mkdir "$lockfile" 2>/dev/null; then
      if is_port_free "$p"; then
        echo "$p"
        return 0
      else
        rmdir "$lockfile" 2>/dev/null || true
      fi
    fi
    i=$((i+1))
  done

  warn "$(msg ERR_CANNOT_RESERVE_PORT)"
  return 1
}

validate_port() {
  port="$1"

  case "$port" in
    ''|*[!0-9]*) return 1 ;;
  esac

  # [v4.7.6 FIX-MED] Reject leading zeros. Otherwise `--port=03306` passes
  # digit + range checks (decimal-parsed to 3306), bypasses
  # is_hard_reserved (which is a STRING `case` matching only "3306"),
  # and the script writes `Port 03306` to sshd_config — which OpenSSH
  # parses as decimal 3306, silently shadowing MySQL. Similar issue
  # for `--port=0022` (script string-compares to "22" elsewhere and
  # treats it as non-standard, racing firewall/SELinux state vs sshd's
  # actual listening port).
  case "$port" in
    0?*) return 1 ;;
  esac

  [ "$port" -ge 1 ] 2>/dev/null && [ "$port" -le 65535 ] 2>/dev/null || return 1

  if [ "$port" -lt 1024 ] && [ "$port" != "22" ]; then
    return 1
  fi

  return 0
}

# ---------------- User & Sudo ----------------
validate_username() {
  raw="$1"
  # [v4.7.0 / MED] printf '%s\n' instead of echo to handle inputs starting
  # with -e / -n safely on shells where /bin/sh resolves to bash.
  u=$(printf '%s' "$raw" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

  # 必须将清洗后的变量回写给全局变量，否则后续 useradd 还是会用带空格的
  TARGET_USER="$u"

  [ "$u" = "root" ] && return 0

  len=${#u}
  [ "$len" -ge 2 ] && [ "$len" -le 32 ] || return 1
  # [v4.7.6 FIX-LOW] Reject embedded newlines BEFORE grep — POSIX grep is
  # per-line-anchored, so a value like "admin\nbadguy" passes since each
  # line individually matches. A simple case-match on the whole value
  # rejects ANY character outside the allowed set including LF/CR.
  case "$u" in
    *[!a-z0-9_-]*) return 1 ;;
  esac
  printf '%s\n' "$u" | grep -Eq '^[a-z_][a-z0-9_-]*$' || return 1

  case "$u" in bin|daemon|adm|lp|sync|shutdown|halt|mail|operator|games|ftp|nobody) return 1 ;; esac
  return 0
}

# [v4.7.0 / HIGH] Wheel/sudo group membership check + stable filename.
safe_configure_sudo() {
  user="$1"
  if [ ! -d /etc/sudoers.d ]; then warn "$(msg WARN_NO_SUDOERS_DIR)"; return 0; fi

  # 1. Is user already explicitly named in /etc/sudoers* with a whitespace boundary?
  if grep -Eq "^[[:space:]]*${user}[[:space:]]" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    info "$(msg INFO_SUDO_EXISTS)"
    return 0
  fi

  # 2. Is user already in a group that grants sudo? Check both explicit
  # membership (id -nG) and the %group rules present in sudoers files.
  user_groups=$(id -nG "$user" 2>/dev/null | tr ' ' '\n')
  if [ -n "$user_groups" ]; then
    for g in wheel sudo admin; do
      if printf '%s\n' "$user_groups" | grep -qx "$g"; then
        # User is in the group AND that group is granted sudo in some config file?
        if grep -Eq "^[[:space:]]*%${g}[[:space:]]" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
          info "$(msg INFO_SUDO_EXISTS) (via group %$g)"
          return 0
        fi
      fi
    done
  fi

  # 3. New sudoers file — stable name per user (idempotent across re-runs).
  #    [v4.7.2 FIX] Write & validate the NEW file BEFORE touching any legacy
  #    files. Previously we removed legacy variants first, which on visudo
  #    failure left the operator with NO sudo at all (lockout).
  sudoers_file="/etc/sudoers.d/server-init-$user"
  # [v4.7.4 FIX-LOW] Symlink defense before write. /etc/sudoers.d is normally
  # 750 root:root but defense-in-depth: a pre-planted symlink would let `cat`
  # overwrite an arbitrary file (e.g. /etc/passwd) with sudoers content.
  unlink_if_symlink "$sudoers_file"
  # [v4.7.2 FIX] umask 337 so the file is born at 0440 (sudoers requires
  # group/world-NON-writable; some sudo builds also warn on world-readable).
  # Default umask (022) would create at 0644 with a brief window before our
  # explicit chmod 440, during which a parallel sudo invocation could warn.
  __sudoers_old_umask=$(umask)
  umask 337
  cat > "$sudoers_file" <<EOF
# Generated by linux-ssh-init-sh v4.7.8
# Stable filename per-user — safe to delete to revoke.
$user ALL=(ALL) NOPASSWD:ALL
Defaults:$user !requiretty
Defaults:$user env_keep += "SSH_AUTH_SOCK"
EOF
  umask "$__sudoers_old_umask"

  if command -v visudo >/dev/null 2>&1; then
    if ! visudo -c -f "$sudoers_file" >/dev/null 2>&1; then
      rm -f "$sudoers_file"
      err "$(msg ERR_SUDOERS_SYNTAX)"
      return 1
    fi
  fi
  if ! chmod 440 "$sudoers_file" 2>/dev/null; then
    rm -f "$sudoers_file"
    err "$(msg ERR_SUDOERS_PERM)"
    return 1
  fi
  chown root:root "$sudoers_file" 2>/dev/null || true
  artifact_track "SUDOERS_FILE=$sudoers_file"
  audit_log "SUDOERS_WRITTEN" "$sudoers_file"

  # 4. [v4.7.2 FIX] Now that the new file is in place, clean up pre-v4.7.0
  #    timestamped variants. Strict pattern: server-init-<user>-<digits-only>
  #    so we cannot accidentally match another user whose name shares this
  #    user's name as a prefix (e.g. cleaning "admin" must NOT remove
  #    "server-init-admin-bot"). Operator-created files like
  #    "server-init-<user>-special-policy" are also preserved.
  for legacy in /etc/sudoers.d/server-init-"$user"-*; do
    [ -f "$legacy" ] || continue
    suffix="${legacy##*/server-init-"$user"-}"
    # Only purely numeric suffixes (the v4.6.x timestamp format) qualify.
    case "$suffix" in
      ''|*[!0-9]*) continue ;;
    esac
    # [v4.7.2 FIX] rm FIRST, then audit_log only on success. The previous
    # ordering wrote the audit-log entry unconditionally — if rm silently
    # failed (read-only fs, immutable bit), the audit trail would falsely
    # claim a removal that never happened.
    if rm -f "$legacy" 2>/dev/null; then
      audit_log "LEGACY_SUDOERS_REMOVED" "$legacy"
      info "Removed pre-v4.7.0 timestamped sudoers: $legacy"
    else
      warn "Failed to remove legacy sudoers file: $legacy"
    fi
  done

  info "$(msg INFO_SUDO_CONFIGURED)"
  return 0
}

get_user_home() {
  user="$1"
  home=""

  if command -v getent >/dev/null 2>&1; then
    home=$(getent passwd "$user" 2>/dev/null | cut -d: -f6)
  fi

  if [ -z "$home" ] && [ -r /etc/passwd ]; then
    home=$(awk -F: -v u="$user" '$1==u {print $6}' /etc/passwd 2>/dev/null)
  fi

  if [ -z "$home" ]; then
    if [ "$user" = "root" ]; then
      home="/root"
    else
      home="/home/$user"
    fi
  fi

  echo "$home"
}

get_user_shell() {
  user="$1"
  shell=""

  if command -v getent >/dev/null 2>&1; then
    shell=$(getent passwd "$user" 2>/dev/null | cut -d: -f7)
  fi

  if [ -z "$shell" ] && [ -r /etc/passwd ]; then
    shell=$(awk -F: -v u="$user" '$1==u {print $7}' /etc/passwd 2>/dev/null)
  fi

  echo "$shell"
}

safe_ensure_user() {
  user="$1"
  [ "$user" = "root" ] && return 0

  if id "$user" >/dev/null 2>&1; then
    shell=$(get_user_shell "$user")
    home_dir=$(get_user_home "$user")

    case "$shell" in
      /bin/bash|/bin/sh|/usr/bin/bash|/usr/bin/sh|/bin/dash|/bin/ash) ;;
      /sbin/nologin|/bin/false|/usr/sbin/nologin)
        warn "$(msg WARN_USER_SHELL) $shell"
        if [ "$AUTO_CONFIRM" != "y" ]; then
          printf "%s" "$(msg ASK_CHANGE_SHELL)"
          read -r change_shell
          if [ "${change_shell:-n}" = "y" ]; then
            new_shell="/bin/sh"
            for try_shell in /bin/bash /bin/ash /bin/sh; do
              [ -x "$try_shell" ] && { new_shell="$try_shell"; break; }
            done
            if command -v chsh >/dev/null 2>&1; then
              chsh -s "$new_shell" "$user" 2>>"$LOG_FILE" || warn "$(msg WARN_CHANGE_SHELL_FAIL)"
            elif command -v usermod >/dev/null 2>&1; then
              usermod -s "$new_shell" "$user" 2>>"$LOG_FILE" || warn "$(msg WARN_CHANGE_SHELL_FAIL)"
            else
              warn "$(msg WARN_CHANGE_SHELL_FAIL)"
            fi
          fi
        fi
        ;;
      "") ;;
      *) warn "$(msg WARN_UNUSUAL_SHELL) $shell" ;;
    esac

    if [ -n "$home_dir" ] && [ -d "$home_dir" ]; then
      dir_owner=""
      if stat -c "%U" "$home_dir" >/dev/null 2>&1; then
        dir_owner=$(stat -c "%U" "$home_dir" 2>/dev/null)
      else
        dir_owner=$(ls -ld "$home_dir" 2>/dev/null | awk '{print $3}')
      fi
      [ -n "$dir_owner" ] && [ "$dir_owner" != "$user" ] && warn "$(msg WARN_HOME_OWNER) $dir_owner"
      [ ! -w "$home_dir" ] && warn "$(msg WARN_HOME_NOT_WRITABLE)"
    fi
    return 0
  fi

  info "$(msg I_USER) $user"
  shell="/bin/sh"
  for test_shell in /bin/bash /usr/bin/bash /bin/ash /bin/sh /usr/bin/sh /bin/dash; do
    if [ -x "$test_shell" ]; then shell="$test_shell"; break; fi
  done

  user_created=0
  if command -v useradd >/dev/null 2>&1; then
    useradd -m -s "$shell" "$user" >>"$LOG_FILE" 2>&1 && user_created=1
  elif command -v adduser >/dev/null 2>&1; then
    adduser -D -s "$shell" "$user" >>"$LOG_FILE" 2>&1 && user_created=1
  fi

  [ "$user_created" -eq 1 ] || { err "$(msg ERR_USER_CREATE_FAIL)"; return 1; }
  id "$user" >/dev/null 2>&1 || { err "$(msg ERR_USER_VERIFY_FAIL)"; return 1; }

  # [v4.7.0] Mark this user as script-created for rollback tracking.
  artifact_track "USER_CREATED=$user"
  # [v4.7.1] Mark for finalize_user_password_policy: this is a NEW account, safe to passwd -d.
  USER_WAS_CREATED="y"
  # [v4.7.4 FIX-MED] Audit trail for user creation (forensic completeness).
  audit_log "USER_CREATED" "user=$user shell=$shell"

  # [v4.7.0 / CRIT] Do NOT clear password here. Previously this was unconditional,
  # which (combined with the fallback "key-failed → keep password auth" policy)
  # could leave a NEW account with no password AND password auth enabled.
  # Password-clear is now deferred to finalize_user_password_policy, which only
  # runs after deploy_keys succeeds.

  # [v4.7.1 FIX-H1 / v4.7.2] Sudoers failure must not be silent.
  if safe_configure_sudo "$user"; then
    SUDO_DEPLOYED="y"
  else
    SUDO_DEPLOYED="n"
    audit_log "SUDO_FAIL" "Could not write sudoers entry for $user"
    if [ "$STRICT_MODE" = "y" ]; then
      err "STRICT: sudoers configuration failed for $user"
      return 1
    fi
    warn "Account $user was created WITHOUT sudo. See $AUDIT_FILE."
  fi
  return 0
}

# [v4.7.0 / v4.7.1] Account password policy applied AFTER key deploy outcome is known.
#
#   New account (USER_WAS_CREATED=y):
#     KEY_OK=y → passwd -d (unlock, key-only auth)
#     KEY_OK=n → leave locked (no password set by useradd anyway). Fallback
#                password-auth must NEVER mean "anyone who knows the username
#                can SSH in passwordlessly".
#
#   Pre-existing account (USER_WAS_CREATED=n) [v4.7.1 fix]:
#     We MUST NOT touch the password. The admin-managed password stays.
#     Key deployment merely ADDS a key; the existing password remains valid
#     for any service that uses it (su, sudo with password, console, etc.).
#
finalize_user_password_policy() {
  user="$1"
  key_ok="$2"
  was_created="$3"
  sudo_ok="${4:-y}"  # default y for backwards compat
  [ "$user" = "root" ] && return 0

  if [ "$was_created" != "y" ]; then
    # [v4.7.1] Pre-existing account: do not clobber its password.
    info "Account $user pre-existed — leaving password state untouched"
    return 0
  fi

  if [ "$key_ok" != "y" ]; then
    warn "Account $user remains locked because key deployment failed"
    ACCOUNT_LOCKED_REASON="key deployment failed"
    audit_log "ACCOUNT_KEPT_LOCKED" "user=$user reason=key_deploy_failed"
    return 0
  fi

  # [v4.7.2 FIX] Be conservative when sudo deployment ALSO failed. A new
  # passwordless+no-sudo account is rarely the operator's intent and means
  # nobody can elevate from it. Keep the account locked so the operator
  # actively notices and fixes it (rather than discovering it later).
  if [ "$sudo_ok" != "y" ]; then
    warn "Account $user kept locked: sudo deployment failed (avoid passwordless+no-sudo)"
    ACCOUNT_LOCKED_REASON="sudo deployment failed"
    audit_log "ACCOUNT_KEPT_LOCKED" "user=$user reason=sudo_deploy_failed"
    return 0
  fi

  if passwd -d "$user" >/dev/null 2>&1; then
    info "Account $user: password cleared (key-only auth)"
    audit_log "PASSWORD_CLEARED" "user=$user method=passwd_-d"
  elif command -v usermod >/dev/null 2>&1 && usermod -p "" "$user" >/dev/null 2>&1; then
    # Some minimal RHEL-family images ship shadow-utils (useradd/usermod) but
    # not the separate passwd(1) package. `usermod -U` refuses to unlock an
    # account when that would leave an empty password, while `passwd -d` would
    # intentionally create exactly that key-only state. Use usermod -p "" as
    # the equivalent fallback after key deployment and sudo setup succeeded.
    info "Account $user: password cleared via usermod -p (key-only auth)"
    audit_log "PASSWORD_CLEARED" "user=$user method=usermod_-p_empty"
  elif usermod -U "$user" >/dev/null 2>&1; then
    info "Account $user: unlocked via usermod"
    audit_log "PASSWORD_CLEARED" "user=$user method=usermod_-U"
  else
    # [v4.7.3 FIX-H2] Both `passwd -d` and `usermod -U` failed — previously
    # silent. Now surface the locked state so the operator sees the warning
    # in print_final_summary instead of an apparent-success banner with a
    # broken account.
    warn "Account $user: passwd -d AND usermod -U both failed — account remains locked"
    ACCOUNT_LOCKED_REASON="passwd-d and usermod-U both failed"
    audit_log "ACCOUNT_KEPT_LOCKED" "user=$user reason=passwd_usermod_both_failed"
  fi
}

# ---------------- Keys ----------------
# [v4.7.0] Hardening: max-filesize, max-redirs, strict-mode requires HTTPS.
# Response is also piped through `head -c` as a belt-and-suspenders DoS guard
# for wget (which lacks --max-filesize). 64 KiB is plenty for a key list.
KEY_MAX_BYTES=65536
KEY_MAX_REDIRS=3

fetch_keys() {
  mode="$1"
  val="$2"
  url=""

  case "$mode" in
    gh)
      # [v4.7.1 FIX-M2] GitHub usernames: 1-39 chars, alphanumeric + hyphen,
      # cannot start or end with hyphen. Anything else → don't substitute it
      # into a URL (avoids path-traversal-style URLs reaching github.com).
      # [v4.7.6 FIX-LOW] Reject embedded newlines / weird bytes BEFORE grep
      # (POSIX grep is per-line-anchored — multi-line strings would each
      # match individually).
      case "$val" in
        *[!A-Za-z0-9-]*) warn "Invalid GitHub username (illegal character): $val"; return 1 ;;
      esac
      if ! printf '%s' "$val" | grep -Eq '^[A-Za-z0-9](-?[A-Za-z0-9]){0,38}$'; then
        warn "Invalid GitHub username (must match ^[A-Za-z0-9](-?[A-Za-z0-9]){0,38}$): $val"
        return 1
      fi
      url="https://github.com/$val.keys" ;;
    url) url="$val" ;;
    raw) printf '%s\n' "$val"; return 0 ;;
    *) return 1 ;;
  esac

  if [ "$mode" = "url" ]; then
    case "$url" in
      https://*) : ;;
      http://*)
        if [ "$STRICT_MODE" = "y" ]; then
          warn "STRICT: refusing plaintext http:// key URL"
          return 1
        fi
        warn "Plaintext http:// URL — keys are public but a MITM could substitute. Prefer https://"
        # [v4.7.5 FIX-LOW] Forensic audit: post-incident analysis needs to
        # know if a key URL was fetched over plaintext. URL itself stays in
        # /var/log/server-init.log debug but is omitted here for redaction.
        audit_log "INSECURE_KEY_URL" "scheme=http non_strict_mode"
        ;;
      *)
        warn "Invalid URL scheme (must be https://, or http:// in non-strict mode)"
        return 1
        ;;
    esac
  fi

  # [v4.7.1 FIX-M3] Download to a TEMP FILE first, then size-check, then emit.
  # The previous design piped curl | head -c which masks curl's max-filesize
  # exit code (63) via SIGPIPE and lets a 1GB-of-junk URL silently succeed
  # with 64KB of attacker-controlled content.
  tmpf=""
  if command -v mktemp >/dev/null 2>&1; then
    tmpf=$(mktemp "$TMP_DIR/fetched_keys.XXXXXX" 2>/dev/null || echo "$TMP_DIR/fetched_keys.$$")
  else
    tmpf="$TMP_DIR/fetched_keys.$$"
  fi
  : > "$tmpf"
  chmod 600 "$tmpf" 2>/dev/null || true

  retries=0
  max_retries=3
  rc=1
  while [ "$retries" -lt "$max_retries" ]; do
    : > "$tmpf"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL \
           --connect-timeout 10 --max-time 30 \
           --max-filesize "$KEY_MAX_BYTES" \
           --max-redirs "$KEY_MAX_REDIRS" \
           --proto '=https,http' \
           "$url" >"$tmpf" 2>>"$LOG_FILE"
      rc=$?
    elif command -v wget >/dev/null 2>&1; then
      # [v4.7.3 FIX-MED] wget has no --max-filesize; instead we set
      # --quota=BYTES which aborts the transfer once exceeded. That bounds
      # the on-disk damage. The post-fetch wc -c size check still applies.
      wget -qO "$tmpf" --timeout=30 \
           --max-redirect="$KEY_MAX_REDIRS" \
           --quota="$KEY_MAX_BYTES" \
           "$url" 2>>"$LOG_FILE"
      rc=$?
    else
      warn "Need curl or wget to fetch keys"
      rm -f "$tmpf" 2>/dev/null
      return 1
    fi

    if [ "$rc" -eq 0 ] && [ -s "$tmpf" ]; then
      # Enforce size cap (paranoid: covers wget which has no max-filesize).
      sz=$(wc -c < "$tmpf" 2>/dev/null | tr -d ' ')
      if [ -n "$sz" ] && [ "$sz" -gt "$KEY_MAX_BYTES" ] 2>/dev/null; then
        warn "Fetched response exceeded $KEY_MAX_BYTES bytes — refusing"
        rm -f "$tmpf" 2>/dev/null
        return 1
      fi
      cat "$tmpf"
      rm -f "$tmpf" 2>/dev/null
      return 0
    fi

    retries=$((retries+1))
    [ "$retries" -lt "$max_retries" ] && sleep 2
  done

  rm -f "$tmpf" 2>/dev/null
  warn "Failed to fetch keys after $max_retries attempts (last rc=$rc)"
  # [v4.7.8 FIX-MED W6-1] Forensic audit: previously, a fetch failure was
  # only `warn`'d. SIEM operators investigating a ROLLBACK had no breadcrumb
  # explaining why the script aborted (the rolled-back artifacts plus a
  # ROLLBACK entry, but no KEY_FETCH_FAILED → no clear cause).
  audit_log "KEY_FETCH_FAILED" "mode=$mode rc=$rc retries=$max_retries"
  return 1
}

# [SEC-FIX] Removed rsa-sha2-256/512 from key type regex (they are signature algorithms, not key types)
validate_ssh_key_line() {
  line="$1"

  line=$(printf '%s' "$line" | tr -d '\000-\037\177' | sed 's/[[:space:]]*#.*$//')
  [ -z "$line" ] && return 1

  # [SEC-FIX] Tightened regex: removed rsa-sha2-256/512, restricted ecdsa to known curves
  if ! printf '%s' "$line" | grep -Eq '^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com|ssh-(rsa|dss|ed25519)-cert-v01@openssh\.com|ecdsa-sha2-nistp(256|384|521)-cert-v01@openssh\.com)[[:space:]]+[A-Za-z0-9+/]+=*([[:space:]]+.*)?$'; then
    return 1
  fi

  key_part=$(printf '%s' "$line" | awk '{print $2}')
  [ -n "$key_part" ] || return 1

  if command -v base64 >/dev/null 2>&1; then
    if ! printf '%s' "$key_part" | base64 -d >/dev/null 2>&1; then
      return 1
    fi
    key_type=$(printf '%s' "$line" | awk '{print $1}')
    key_bytes=$(printf '%s' "$key_part" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
    case "$key_type" in
      ssh-rsa)
        [ -n "$key_bytes" ] && [ "$key_bytes" -ge 256 ] 2>/dev/null || return 1 ;;
      ssh-ed25519|sk-ssh-ed25519@openssh.com)
        [ -n "$key_bytes" ] && [ "$key_bytes" -ge 32 ] 2>/dev/null || return 1 ;;
      ssh-dss)
        [ -n "$key_bytes" ] && [ "$key_bytes" -ge 40 ] 2>/dev/null || return 1 ;;
    esac
  fi

  # [v4.7.0] Use mktemp so concurrent validations in a `while read` loop
  # cannot collide on the same filename inside TMP_DIR.
  if command -v ssh-keygen >/dev/null 2>&1; then
    if command -v mktemp >/dev/null 2>&1; then
      tmpk=$(mktemp "$TMP_DIR/keycheck.XXXXXX" 2>/dev/null || echo "$TMP_DIR/keycheck.$$")
    else
      tmpk="$TMP_DIR/keycheck.$$"
    fi
    printf '%s\n' "$line" > "$tmpk"
    if ! ssh-keygen -l -f "$tmpk" >/dev/null 2>&1; then
      rm -f "$tmpk" 2>/dev/null || true
      return 1
    fi
    rm -f "$tmpk" 2>/dev/null || true
  fi

  printf "%s\n" "$line"
  return 0
}

# [SEC-FIX] Completely rewritten deploy_keys with symlink protection
deploy_keys() {
  user="$1"
  keys="$2"
  home=$(get_user_home "$user")
  dir="$home/.ssh"
  auth="$dir/authorized_keys"

  # [v4.7.3 FIX-H3] Defensive home-path validation. /etc/passwd is the source
  # of truth, but if it has been tampered with (e.g. someone set a
  # non-root user's home to /root or /etc), deploy_keys would happily mkdir
  # .ssh inside it and chown to the unprivileged user — instant escalation.
  # Whitelist the realistic home-dir prefixes.
  case "$home" in
    /home/*|/Users/*|/var/lib/*) : ;;  # standard user homes
    /root)
      # Only allowed when the target user IS root.
      if [ "$user" != "root" ]; then
        err "Refusing to deploy keys for non-root user '$user' into /root"
        return 1
      fi ;;
    /*) :
      # Other absolute paths permitted only if the directory is already owned
      # by the target user (operator's existing custom layout). Reject if
      # owned by someone else (defends against the tampered-/etc/passwd case).
      ;;
    *)
      err "Refusing: home dir '$home' is not an absolute path"
      return 1 ;;
  esac

  # [SEC-FIX] Refuse symlink home directory (local privilege escalation prevention)
  [ -z "$home" ] && { err "$(msg ERR_HOME_NOT_DIR)"; return 1; }
  if [ -L "$home" ]; then
    err "$(msg ERR_HOME_SYMLINK): $home"
    return 1
  fi
  if [ ! -d "$home" ]; then
    err "$(msg ERR_HOME_NOT_DIR): $home"
    return 1
  fi

  # [v4.7.3 FIX-H3] Refuse to deploy keys into a directory that isn't owned
  # by the target user (or by root, for root). Catches tampered /etc/passwd
  # pointing a user's home at /root, /etc, etc.
  home_owner=""
  if stat -c "%U" "$home" >/dev/null 2>&1; then
    home_owner=$(stat -c "%U" "$home" 2>/dev/null)
  else
    home_owner=$(ls -ld "$home" 2>/dev/null | awk '{print $3}')
  fi
  if [ -n "$home_owner" ]; then
    case "$user:$home_owner" in
      root:root) : ;;                # root → /root, fine
      *:"$user") : ;;                # user → user-owned dir, fine
      *)
        err "Refusing: $home is owned by '$home_owner', not '$user'. /etc/passwd may be tampered."
        return 1 ;;
    esac
  fi

  # [SEC-FIX] Refuse symlink .ssh directory
  if [ -L "$dir" ]; then
    err "$(msg ERR_SSH_DIR_SYMLINK): $dir"
    return 1
  fi
  if [ -e "$dir" ] && [ ! -d "$dir" ]; then
    err "$(msg ERR_SSH_DIR_NOT_DIR): $dir"
    return 1
  fi

  mkdir -p "$dir" 2>/dev/null || return 1
  chmod 700 "$dir" 2>/dev/null || true

  # [SEC-FIX] Refuse symlink authorized_keys
  if [ -L "$auth" ]; then
    err "$(msg ERR_AUTH_KEYS_SYMLINK): $auth"
    return 1
  fi
  if [ -e "$auth" ] && [ ! -f "$auth" ]; then
    err "$(msg ERR_AUTH_KEYS_NOT_FILE): $auth"
    return 1
  fi

  touch "$auth" 2>/dev/null || return 1
  chmod 600 "$auth" 2>/dev/null || true

  # [SEC-FIX] Only chown specific paths, no -R (symlink traversal risk)
  chown "${user}:" "$dir" "$auth" 2>/dev/null || chown "$user" "$dir" "$auth" 2>/dev/null || true

  # [v4.7.0 / MED] Verify ownership stuck. On NFS root_squash or restrictive
  # filesystems chown can silently fail and leave files owned by root, which
  # sshd then refuses to read ("bad ownership"). Catch this BEFORE we disable
  # password auth on the strength of "KEY_OK=y".
  actual_owner=$(stat -c "%U" "$auth" 2>/dev/null || ls -l "$auth" 2>/dev/null | awk '{print $3}')
  if [ -n "$actual_owner" ] && [ "$actual_owner" != "$user" ]; then
    err "deploy_keys: $auth owned by '$actual_owner' (expected '$user') — sshd will reject. Aborting."
    return 1
  fi

  valid_keys_file="$TMP_DIR/valid_keys.$$"
  deployed_count=0
  
  : > "$valid_keys_file"

  printf "%s\n" "$keys" | while IFS= read -r line; do
    [ -z "$line" ] && continue
    clean_line=$(validate_ssh_key_line "$line")
    if [ -n "$clean_line" ]; then
      printf "%s\n" "$clean_line" >> "$valid_keys_file"
    fi
  done

  if [ ! -s "$valid_keys_file" ]; then
    warn "$(msg WARN_NO_VALID_KEYS)"
    rm -f "$valid_keys_file" 2>/dev/null || true
    return 1
  fi

  while IFS= read -r key; do
    [ -z "$key" ] && continue
    if ! grep -qxF "$key" "$auth" 2>/dev/null; then
      printf "%s\n" "$key" >> "$auth"
    fi
    if grep -qxF "$key" "$auth" 2>/dev/null; then
      deployed_count=$((deployed_count + 1))
    fi
  done < "$valid_keys_file"

  rm -f "$valid_keys_file" 2>/dev/null || true

  if [ "$deployed_count" -gt 0 ]; then
    info "$(msg INFO_KEYS_DEPLOYED) $deployed_count"
    audit_log "KEYS_DEPLOYED" "user=$user count=$deployed_count auth=$auth"
    return 0
  else
    warn "$(msg WARN_NO_VALID_KEYS)"
    return 1
  fi
}

# ---------------- sshd_config management ----------------
# [SEC-FIX] Case-insensitive directive matching
cleanup_sshd_config_d() {
  if [ -d "$SSH_CONF_D" ]; then
    for conf in "$SSH_CONF_D"/*.conf; do
      [ -f "$conf" ] || continue
      # [SEC-FIX] Case-insensitive matching
      if awk '
        BEGIN { found = 0 }
        {
          line = tolower($0)
          if (line ~ /^[[:space:]]*(port|permitrootlogin|passwordauthentication|pubkeyauthentication|challengeresponseauthentication|kbdinteractiveauthentication|kexalgorithms|ciphers|macs|addressfamily|listenaddress)[[:space:]]/) {
            found = 1
            exit
          }
        }
        END { exit !found }
      ' "$conf" 2>/dev/null; then
        # [v4.7.3 FIX-H4] If a stale .bak_server_init from a prior crashed
        # run already exists, do NOT overwrite it (we'd lose the original
        # snapshot). Pick a timestamped name so both are preserved.
        # Append $$ as well so two runs in the same second never collide.
        target="${conf}.bak_server_init"
        if [ -e "$target" ]; then
          target="${conf}.bak_server_init.$(date +%s 2>/dev/null || echo 0).$$"
          warn "Pre-existing $conf.bak_server_init kept; using $target"
        fi
        mv "$conf" "$target" 2>/dev/null || true
        audit_log "DROPIN_RENAMED" "$conf -> $target"
        warn "$(msg CLEAN_D) $conf"
      fi
    done
  fi
}

remove_managed_block() {
  tmp_in="$TMP_DIR/sshd_config.in"
  tmp_out="$TMP_DIR/sshd_config.out"
  cp -p "$SSH_CONF" "$tmp_in" 2>/dev/null || true
  # [v4.7.0 / MED] Tolerate CRLF endings, leading whitespace and trailing
  # whitespace on the marker lines so a hand-edited file still gets cleaned.
  awk -v b="$BLOCK_BEGIN" -v e="$BLOCK_END" '
    function norm(s) {
      sub(/\r$/, "", s)
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    {
      n = norm($0)
      if (n == b) { skip = 1; next }
      if (n == e) { skip = 0; next }
      if (skip != 1) print
    }
  ' "$tmp_in" >"$tmp_out"
  if [ -s "$tmp_out" ]; then
    cat "$tmp_out" > "$SSH_CONF"
  fi
}

# [SEC-FIX] Case-insensitive sanitization
sanitize_sshd_config() {
  info "$(msg INFO_SANITIZE_DUP)"
  tmp_san="$TMP_DIR/sshd_config.sanitized"

  # [SEC-FIX] Case-insensitive matching with tolower()
  # [v4.7.3 FIX-MED] Stop sanitizing once a `Match` block is seen. Directives
  # inside Match blocks are scope-restricted by design and our managed-block
  # comment-out would silently disable operator-intended overrides.
  awk '
    {
      low = tolower($0)
    }
    # Once we hit a Match directive, just pass everything through unchanged.
    in_match { print; next }
    low ~ /^[[:space:]]*match[[:space:]]/ { in_match = 1; print; next }
    low ~ /^[[:space:]]*port[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*permitrootlogin[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*passwordauthentication[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*pubkeyauthentication[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*challengeresponseauthentication[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*kbdinteractiveauthentication[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*kexalgorithms[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*ciphers[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*macs[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*addressfamily[[:space:]]/ { print "# [server-init disabled] " $0; next }
    low ~ /^[[:space:]]*listenaddress[[:space:]]/ { print "# [server-init disabled] " $0; next }
    { print }
' "$SSH_CONF" > "$tmp_san"

  if [ -s "$tmp_san" ]; then
    cat "$tmp_san" > "$SSH_CONF"
  fi
}

has_global_ipv6() {
  if command -v ip >/dev/null 2>&1; then
    ip -6 addr show scope global 2>/dev/null | grep -q inet6 && return 0
  fi
  
  if [ -f /proc/net/if_inet6 ]; then
    awk '$4 == "00" && $6 != "lo" { found=1; exit } END { exit !found }' /proc/net/if_inet6 2>/dev/null && return 0
  fi
  
  if command -v ifconfig >/dev/null 2>&1; then
    ifconfig 2>/dev/null | grep -i 'inet6.*global' >/dev/null 2>&1 && return 0
  fi
  
  return 1
}

# ----- Crypto selection -----
csv_contains() {
  csv="$1"
  item="$2"
  case ",$csv," in
    *,"$item",*) return 0 ;;
    *) return 1 ;;
  esac
}

csv_intersect_ordered() {
  pref="$1"
  supp="$2"
  result=""
  
  result=$(
    IFS=,
    for a in $pref; do
      if [ -n "$a" ] && csv_contains "$supp" "$a"; then
        printf "%s\n" "$a"
      fi
    done
  )
  
  echo "$result" | tr '\n' ',' | sed 's/,$//'
}

get_sshd_T_value() {
  key="$1"
  v=""
  
  if openssh_version_ge 6 8; then
    v=$(sshd -T -C user=root,host=localhost,addr=127.0.0.1 -f "$SSH_CONF" 2>/dev/null | awk -v k="$key" 'tolower($1)==k {print $2; exit}')
  fi
  
  if [ -z "$v" ]; then
    v=$(sshd -T -f "$SSH_CONF" 2>/dev/null | awk -v k="$key" 'tolower($1)==k {print $2; exit}')
  fi
  
  echo "$v"
}

compute_crypto_lines() {
  KEX_LINE=""
  CIPHERS_LINE=""
  MACS_LINE=""
  CRYPTO_MODE="skip"

  if ! command -v sshd >/dev/null 2>&1; then
    CRYPTO_MODE="skip"
    return 0
  fi

  supp_kex=$(get_sshd_T_value "kexalgorithms")
  supp_ciphers=$(get_sshd_T_value "ciphers")
  supp_macs=$(get_sshd_T_value "macs")

  pref_kex="curve25519-sha256@libssh.org,curve25519-sha256,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512"
  pref_ciphers="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
  pref_macs="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com"

  if [ -n "$supp_kex" ] || [ -n "$supp_ciphers" ] || [ -n "$supp_macs" ]; then
    sel_kex=$(csv_intersect_ordered "$pref_kex" "$supp_kex")
    sel_ciphers=$(csv_intersect_ordered "$pref_ciphers" "$supp_ciphers")
    sel_macs=$(csv_intersect_ordered "$pref_macs" "$supp_macs")

    [ -n "$sel_kex" ] && KEX_LINE="KexAlgorithms $sel_kex"
    [ -n "$sel_ciphers" ] && CIPHERS_LINE="Ciphers $sel_ciphers"
    [ -n "$sel_macs" ] && MACS_LINE="MACs $sel_macs"

    if [ -n "$KEX_LINE" ] || [ -n "$CIPHERS_LINE" ] || [ -n "$MACS_LINE" ]; then
      CRYPTO_MODE="filtered"
    else
      CRYPTO_MODE="skip"
    fi
    return 0
  fi

  if openssh_version_ge 6 5; then
    KEX_LINE="KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"
    CIPHERS_LINE="Ciphers chacha20-poly1305@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
    MACS_LINE="MACs hmac-sha2-512,hmac-sha2-256"
    CRYPTO_MODE="fallback"
  else
    CRYPTO_MODE="skip"
  fi
}

build_block() {
  file="$1"
  {
    echo "$BLOCK_BEGIN"
    echo "# Managed by server-init v4.7.8"
    echo "# Generated: $(date)"
    echo "# OpenSSH: ${OPENSSH_VER_MAJOR}.${OPENSSH_VER_MINOR}"
    echo "# Do NOT edit inside this block. Changes will be overwritten."
    echo ""

    echo "Port $SSH_PORT"

    [ -n "$KEX_LINE" ] && echo "$KEX_LINE"
    [ -n "$CIPHERS_LINE" ] && echo "$CIPHERS_LINE"
    [ -n "$MACS_LINE" ] && echo "$MACS_LINE"

    if [ "$IPV6_ENABLED" = "y" ]; then
      echo "AddressFamily any"
      # [FIX-AWS] Debian 12 Socket Activation 冲突修复: 不显式指定监听地址
      # echo "ListenAddress ::"
      # echo "ListenAddress 0.0.0.0"
    else
      echo "AddressFamily inet"
      # echo "ListenAddress 0.0.0.0"
    fi

    if [ "$KEY_OK" = "y" ]; then
      echo "PasswordAuthentication no"
      echo "PermitEmptyPasswords no"
      echo "ChallengeResponseAuthentication no"
      echo "PubkeyAuthentication yes"
      # [SEC-FIX] Add KbdInteractiveAuthentication no for true key-only auth
      if [ "$SUPPORTS_KBD_INTERACTIVE" = "y" ]; then
        echo "KbdInteractiveAuthentication no"
      fi
    else
      echo "PasswordAuthentication yes"
      echo "PubkeyAuthentication yes"
    fi

    if [ "$TARGET_USER" = "root" ]; then
      if [ "$KEY_OK" = "y" ]; then
        if openssh_version_ge 7 0; then
          echo "PermitRootLogin prohibit-password"
        else
          echo "PermitRootLogin without-password"
        fi
      else
        echo "PermitRootLogin yes"
      fi
    else
      if [ "$KEY_OK" = "y" ]; then
        echo "PermitRootLogin no"
      else
        if [ "$ROOT_KEY_PRESENT" = "y" ]; then
          if openssh_version_ge 7 0; then
            echo "PermitRootLogin prohibit-password"
          else
            echo "PermitRootLogin without-password"
          fi
        else
          echo "PermitRootLogin yes"
        fi
      fi
    fi

    echo ""
    echo "$BLOCK_END"
  } >"$file"
}

install_managed_block() {
  block="$1"
  tmp="$TMP_DIR/sshd_config.merge"

  match_line=$(awk '/^[[:space:]]*#/ {next} /^[[:space:]]*Match[[:space:]]/ {print NR; exit}' "$SSH_CONF" 2>/dev/null)

  if [ -z "$match_line" ]; then
    cat "$block" "$SSH_CONF" > "$tmp"
  else
    info "$(msg INFO_MATCH_INSERT)"
    cat "$block" "$SSH_CONF" > "$tmp"
  fi

  chmod 600 "$tmp" 2>/dev/null || true
  # [v4.7.0 / MED] Fail loudly if rename fails (e.g. cross-device) so we don't
  # silently continue with the old config being "validated" by later steps.
  mv "$tmp" "$SSH_CONF" || die "install_managed_block: failed to mv $tmp → $SSH_CONF"
  audit_log "MANAGED_BLOCK_INSTALLED" "config=$SSH_CONF port=$SSH_PORT"
}

verify_sshd_listening() {
  port="$1"
  timeout_s=30  # [FIX] 延长至 30 秒，适应 Vultr 等慢速机器
  elapsed=0

  ensure_port_tools

  while [ "$elapsed" -lt "$timeout_s" ]; do
    if ! is_port_free "$port"; then
      return 0
    fi
    if command -v nc >/dev/null 2>&1; then
      # [SEC-FIX] Use 127.0.0.1 instead of localhost
      # [兼容性优化]
      # 1. 尝试 IPv4 本地回环 (大多数系统的标准情况)
      # 2>/dev/null 屏蔽了不支持 IPv4 时的报错
      nc -z -w 1 127.0.0.1 "$port" 2>/dev/null && return 0
      # 2. 尝试 IPv6 本地回环 (针对 Debian 12 默认开启 bindv6only 的情况)
      # 如果系统不支持 IPv6，这行命令会静默失败，不会中断脚本
      nc -z -w 1 ::1 "$port" >/dev/null 2>&1 && return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

# [SEC-FIX] Use 127.0.0.1 instead of localhost to avoid IPv6 mismatch
enhanced_ssh_test() {
  port="$1"
  user="$2"
  info "$(msg TEST_CONN)"

  if ! verify_sshd_listening "$port"; then
    err "SSHD not listening on port $port"
    return 1
  fi

  banner_ok=0
  if command -v nc >/dev/null 2>&1; then
    proto=""
    # [SEC-FIX] Use 127.0.0.1 instead of localhost
    if command -v timeout >/dev/null 2>&1; then
      proto=$(printf "SSH-2.0-TEST\r\n" | timeout 3 nc 127.0.0.1 "$port" 2>/dev/null || true)
    else
      proto=$(printf "SSH-2.0-TEST\r\n" | nc -w 3 127.0.0.1 "$port" 2>/dev/null || true)
    fi
    
    if echo "$proto" | grep -q "SSH-2.0"; then
      ok "$(msg INFO_SSH_PROTOCOL_OK)"
      banner_ok=1
    else
      err "$(msg ERR_NO_BANNER)"
    fi
  else
    warn "nc not available, skipping banner check"
    banner_ok=1
  fi

  if [ "$banner_ok" -ne 1 ]; then
    return 1
  fi

  attempts=1
  max_attempts=3
  success=0
  while [ "$attempts" -le "$max_attempts" ]; do
    if command -v ssh >/dev/null 2>&1; then
      # [SEC-FIX] Use -4 flag and 127.0.0.1
      if ssh -4 -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
           -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null \
           -p "$port" "$user@127.0.0.1" "exit 0" >/dev/null 2>&1; then
        success=1
        break
      fi
      # 尝试 1: IPv4 回环 (主流情况)
      if ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
             -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null \
             -p "$port" "$user@127.0.0.1" "exit 0" >/dev/null 2>&1; then
           success=1
           break
      fi
      # 尝试 2: IPv6 回环 (针对纯 IPv6 环境的备选)
      if ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
             -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null \
             -p "$port" "$user@::1" "exit 0" >/dev/null 2>&1; then
           success=1
           break
      fi
    fi
    attempts=$((attempts + 1))
    [ "$attempts" -le "$max_attempts" ] && sleep 1
  done

  if [ "$success" -eq 1 ]; then
    ok "$(msg TEST_OK)"
    audit_log "LOGIN_TEST_PASSED" "user=$user port=$port"
  else
    # [v4.7.3 NOTE] An ssh-client login test launched from root with no
    # client-side private key for $user cannot succeed; this is EXPECTED in
    # the vast majority of runs. We've already validated server health via
    # `sshd -t`, `verify_sshd_listening`, and an SSH-2.0 banner exchange.
    # So this branch is informational, not a server-side failure signal.
    warn "$(msg WARN_PORT_OPEN_BUT_FAIL)"
    audit_log "LOGIN_TEST_INCONCLUSIVE" "user=$user port=$port (expected when root lacks client key)"
  fi

  return 0
}

update_motd() {
  info "$(msg MOTD_UPD)"

  # ---------------------------------------------------------
  # 1. 清理 /etc/motd 中的历史 server-init 遗留行，并保留一份真实 .bak
  #    [v4.7.1 FIX-R3] motd mutation is now tracked as an artifact so that
  #    rollback can restore the original from .bak.
  # ---------------------------------------------------------
  motd="/etc/motd"
  if [ -f "$motd" ]; then
    motd_changed=0
    # First time only — preserve real .bak; subsequent runs keep that bak.
    if [ ! -f "${motd}.bak" ]; then
      cp -p "$motd" "${motd}.bak" 2>/dev/null && motd_changed=1
    fi
    # [v4.7.3 FIX-MED] Anchor patterns to start-of-line so the operator's own
    # MOTD lines that happen to contain "Login User:" or similar text are not
    # accidentally stripped. Older versions used unanchored grep which could
    # eat user content.
    if grep -qE "^[[:space:]]*(Server Init|Login User:|SSH Port:|Auth Type:|Firewall:)|^={10,}" "$motd" 2>/dev/null; then
      grep -vE "^[[:space:]]*(Server Init|Login User:|SSH Port:|Auth Type:|Firewall:)|^={10,}" "$motd" > "${motd}.clean" 2>/dev/null
      if [ -f "${motd}.clean" ]; then
        mv "${motd}.clean" "$motd" 2>/dev/null || rm -f "${motd}.clean" 2>/dev/null
        motd_changed=1
      fi
    fi
    if [ "$motd_changed" = "1" ] && [ -f "${motd}.bak" ]; then
      artifact_track "MOTD_BAK=$motd"
    fi
  fi

  # ---------------------------------------------------------
  # 2. 写出动态登录横幅（POSIX 兼容；颜色用 printf %b 避免 dash 字面输出）
  # ---------------------------------------------------------
  mkdir -p /etc/profile.d 2>/dev/null || true
  banner_file="/etc/profile.d/z99-ssh-init-banner.sh"
  # [v4.7.4 FIX-LOW] Symlink defense.
  unlink_if_symlink "$banner_file"

  # [v4.7.0 / HIGH] Values are validated upstream ($SSH_PORT digits-only,
  # $FINAL_AUTH from a fixed set) — write the final form directly in one
  # heredoc instead of a heredoc + post-sed pass (no race window).
  if [ "$KEY_OK" = "y" ]; then
    final_auth="Key Only (Secure)"
  else
    final_auth="Password/Key"
  fi

  cat > "$banner_file" <<EOF
#!/bin/sh
# Generated by linux-ssh-init-sh v4.7.8
# Login banner: prefers live sshd_config values, falls back to install-time values.
SSH_CONF="/etc/ssh/sshd_config"
REAL_PORT="$SSH_PORT"
AUTH_TYPE="$final_auth"
REAL_USER=\$(whoami 2>/dev/null || echo "unknown")

# Refresh from live config if readable (root sessions).
if [ -r "\$SSH_CONF" ]; then
    CONF_PORT=\$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print \$2}' "\$SSH_CONF" | tail -n 1)
    [ -n "\$CONF_PORT" ] && REAL_PORT="\$CONF_PORT"
    if grep -Ei '^[[:space:]]*PasswordAuthentication[[:space:]]+yes' "\$SSH_CONF" >/dev/null 2>&1; then
        AUTH_TYPE="Password/Key"
    else
        AUTH_TYPE="Key Only (Secure)"
    fi
fi

printf '\n'
printf '%b===============================================================================%b\n' "\033[0;36m" "\033[0m"
printf '%b                       Server Init Managed - SSH Hardened%b\n' "\033[0;36m" "\033[0m"
printf '%b===============================================================================%b\n' "\033[0;36m" "\033[0m"
printf ' Login User: %b%s%b\n' "\033[1;32m" "\$REAL_USER" "\033[0m"
printf ' SSH Port:   %b%s%b (Dynamic Check)\n' "\033[1;32m" "\$REAL_PORT" "\033[0m"
printf ' Auth Type:  %s\n' "\$AUTH_TYPE"
printf ' Firewall:   Please ensure TCP/%b%s%b is allowed.\n' "\033[1;33m" "\$REAL_PORT" "\033[0m"
printf '%b===============================================================================%b\n' "\033[0;36m" "\033[0m"
printf '\n'
EOF

  chown root:root "$banner_file" 2>/dev/null || true
  chmod 0644 "$banner_file" 2>/dev/null || true
  artifact_track "PROFILE_D_BANNER=$banner_file"
  audit_log "MOTD_BANNER_WRITTEN" "$banner_file"
}

generate_health_report() {
  report_file="/var/log/server-init-health.log"
  end_time=$(date +%s)
  duration=$((end_time - SCRIPT_START_TIME))
  sys_uptime=$(uptime -p 2>/dev/null || uptime 2>/dev/null | awk -F, '{print $1}')

  # [v4.7.0] Pre-compute fields with if/then/else (avoids &&...|| precedence trap)
  if [ "$KEY_OK" = "y" ]; then key_auth_label="YES"; else key_auth_label="NO"; fi
  if [ "$IPV6_ENABLED" = "y" ]; then ipv6_label="Enabled"; else ipv6_label="Disabled"; fi
  if is_port_free "$SSH_PORT"; then port_label="NOT LISTENING (Error)"; else port_label="LISTENING (OK)"; fi

  {
    echo "=== Server Init Health Report ==="
    echo "Generated: $(date)"
    echo "Version: v4.7.8 Enterprise Hardening"
    echo "Execution Time: ${duration}s"
    echo ""
    echo "--- System ---"
    echo "Uptime: $sys_uptime"
    echo "OpenSSH: ${OPENSSH_VER_MAJOR}.${OPENSSH_VER_MINOR}"
    echo ""
    echo "--- SSH Config ---"
    echo "Port: $SSH_PORT"
    echo "User: $TARGET_USER"
    echo "KeyAuth: $key_auth_label"
    # [v4.7.2] Surface locked-account state if applicable.
    if [ -n "$ACCOUNT_LOCKED_REASON" ]; then
      echo "AccountLocked: YES ($ACCOUNT_LOCKED_REASON)"
    else
      echo "AccountLocked: NO"
    fi
    echo ""
    echo "--- Network ---"
    echo "IPv6: $ipv6_label"
    echo "Port Status: $port_label"
    echo "Crypto Mode: $CRYPTO_MODE"
  } > "$report_file" 2>/dev/null || true
  chmod 600 "$report_file" 2>/dev/null || true
  info "Health report saved to: $report_file"
}

print_final_summary() {
  public_ip=""
  # [v4.7.0] Gate external lookup behind a flag for offline / air-gapped use.
  # [v4.7.1 FIX-M8] Apply the same protocol/redirect hardening as fetch_keys.
  if [ "$ARG_NO_IP_PROBE" != "y" ] && command -v curl >/dev/null 2>&1; then
    public_ip=$(curl -4fsSL --max-time 2 \
                     --max-redirs 2 \
                     --proto '=https' \
                     https://api.ipify.org 2>/dev/null || echo "")
    # [v4.7.6 FIX-LOW] Sanitize: a hostile (or MITM'd) ipify response could
    # contain ANSI CSI sequences that the operator's terminal renders.
    # Strip everything except IPv4 chars + length cap.
    public_ip=$(printf '%s' "$public_ip" | tr -cd '0-9.' | cut -c1-15)
  fi

  local_ip=""
  if command -v hostname >/dev/null 2>&1; then
    local_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  fi
  if [ -z "$local_ip" ] && command -v ip >/dev/null 2>&1; then
    local_ip=$(ip -4 addr show 2>/dev/null | awk '
      /inet / {
        ip=$2
        sub(/\/.*/, "", ip)
        if (ip !~ /^127\./) { print ip; exit }
      }
    ')
  fi

  end_time=$(date +%s)
  duration=$((end_time - SCRIPT_START_TIME))

  # [v4.7.0] Use %b for ANSI sequences so dash interprets them correctly
  echo ""
  printf '%b╔════════════════════════════════════════════════════════════════════╗%b\n' "$CYAN" "$NC"
  printf '%b║ %-66s ║%b\n' "$CYAN" "$(msg BOX_TITLE)" "$NC"
  printf '%b╠════════════════════════════════════════════════════════════════════╣%b\n' "$CYAN" "$NC"
  printf '%b║ %-66s ║%b\n' "$CYAN" " $(msg BOX_SSH)" "$NC"
  # [v4.7.3 FIX-LOW] If the account is locked, do NOT print the ssh command —
  # it won't work and operators have copy-pasted such hints to their grief.
  # Show a placeholder instead, the explicit warning block below explains.
  if [ -n "$ACCOUNT_LOCKED_REASON" ]; then
    printf '%b║     (ssh command suppressed: account is locked, see below)    %-3s ║%b\n' "$CYAN" "" "$NC"
  else
    if [ -n "$public_ip" ]; then
      printf '%b║     Public: ssh -p %-5s %s@%s %-16s ║%b\n' "$CYAN" "$SSH_PORT" "$TARGET_USER" "$public_ip" "" "$NC"
    fi
    if [ -n "$local_ip" ]; then
      printf '%b║     Local:  ssh -p %-5s %s@%s %-16s ║%b\n' "$CYAN" "$SSH_PORT" "$TARGET_USER" "$local_ip" "" "$NC"
    fi
  fi
  printf '%b║                                                                    ║%b\n' "$CYAN" "$NC"

  if [ "$KEY_OK" = "y" ]; then
    printf '%b║ %-66s ║%b\n' "$CYAN" " $(msg BOX_KEY_ON)" "$NC"
  else
    printf '%b║ %-66s ║%b\n' "$CYAN" " $(msg BOX_KEY_OFF)" "$NC"
  fi

  if [ "$SSH_PORT" != "22" ]; then
    printf '%b║ %-66s ║%b\n' "$CYAN" " $(msg BOX_PORT)$SSH_PORT" "$NC"
    printf '%b║ %-66s ║%b\n' "$CYAN" " $(msg BOX_FW)" "$NC"
    if is_k8s_nodeport "$SSH_PORT"; then
      printf '%b║ %-66s ║%b\n' "$CYAN" " $(msg BOX_K8S_WARN)" "$NC"
    fi
  fi

  # [v4.7.2] Show explicit locked-account warning if applicable, so the
  # operator doesn't blindly try the SSH command above.
  # Truncate the username at 20 chars for box-width safety (printf %-66s pads
  # but never truncates; a 32-char name would push the right border past col 66).
  if [ -n "$ACCOUNT_LOCKED_REASON" ]; then
    short_user=$(printf '%.20s' "$TARGET_USER")
    short_reason=$(printf '%.50s' "$ACCOUNT_LOCKED_REASON")
    printf '%b║                                                                    ║%b\n' "$CYAN" "$NC"
    printf '%b║ %-66s ║%b\n' "$CYAN" " ! ACCOUNT LOCKED: $short_user cannot SSH yet"      "$NC"
    printf '%b║ %-66s ║%b\n' "$CYAN" "   Reason: $short_reason"                          "$NC"
    printf '%b║ %-66s ║%b\n' "$CYAN" "   Fix: passwd -d $short_user (then test SSH)"    "$NC"
  fi

  printf '%b║                                                                    ║%b\n' "$CYAN" "$NC"
  printf '%b║ %-66s ║%b\n' "$CYAN" " $(msg BOX_WARN)" "$NC"
  printf '%b╚════════════════════════════════════════════════════════════════════╝%b\n' "$CYAN" "$NC"
  echo ""
  echo "Log:    $LOG_FILE"
  echo "Audit:  $AUDIT_FILE"
  echo "Health: /var/log/server-init-health.log"
  echo "Time:   ${duration}s"
}

validate_ssh_config_comprehensive() {
  config_file="$1"
  user="$2"
  key_ok="$3"

  if ! sshd -t -f "$config_file" 2>>"$LOG_FILE"; then
    err "SSH Config Syntax Error"
    return 1
  fi

  # [v4.7.0 / HIGH] Use sshd -T (effective config) instead of grep|tail|$NF.
  # The previous approach picked the LAST matching line which may live inside
  # a `Match` block, giving the wrong effective value at the global scope.
  # sshd -T resolves Match blocks against the simulated identity below.
  sshd_T_out=""
  if openssh_version_ge 6 8; then
    sshd_T_out=$(sshd -T -C "user=$user,host=localhost,addr=127.0.0.1" -f "$config_file" 2>>"$LOG_FILE" || true)
  fi
  if [ -z "$sshd_T_out" ]; then
    sshd_T_out=$(sshd -T -f "$config_file" 2>>"$LOG_FILE" || true)
  fi

  if [ -n "$sshd_T_out" ]; then
    password_auth=$(printf '%s\n' "$sshd_T_out" | awk 'tolower($1)=="passwordauthentication" {print tolower($2); exit}')
    pubkey_auth=$(printf '%s\n' "$sshd_T_out"   | awk 'tolower($1)=="pubkeyauthentication"   {print tolower($2); exit}')
    port_setting=$(printf '%s\n' "$sshd_T_out"  | awk 'tolower($1)=="port"                   {print $2; exit}')
  else
    # [v4.7.1 FIX-H3] sshd -T failed in BOTH variants — usually means a Match
    # block prevents `-T` without proper `-C`, or sshd is too old. The grep
    # fallback is approximate and can be wrong inside Match blocks. STRICT
    # mode refuses to proceed on approximate validation.
    err "sshd -T produced no output (Match block + old sshd?). Validation will be approximate."
    if [ "$STRICT_MODE" = "y" ]; then
      die "STRICT: refusing to apply config without authoritative sshd -T validation"
    fi
    warn "Continuing with grep-based fallback — values inside Match blocks may give wrong answers"
    password_auth=$(grep -Ei '^[[:space:]]*PasswordAuthentication[[:space:]]' "$config_file" 2>/dev/null | awk '{print $NF}' | tr -d '\r' | tail -1 | tr '[:upper:]' '[:lower:]')
    pubkey_auth=$(grep -Ei '^[[:space:]]*PubkeyAuthentication[[:space:]]' "$config_file" 2>/dev/null   | awk '{print $NF}' | tr -d '\r' | tail -1 | tr '[:upper:]' '[:lower:]')
    port_setting=$(grep -Ei '^[[:space:]]*Port[[:space:]]' "$config_file" 2>/dev/null                  | awk '{print $NF}' | tr -d '\r' | tail -1)
  fi

  [ -n "$password_auth" ] || password_auth="yes"
  [ -n "$pubkey_auth" ]   || pubkey_auth="yes"
  [ -n "$port_setting" ]  || port_setting="22"

  if [ "$password_auth" = "no" ] && [ "$pubkey_auth" = "no" ]; then
    die "$(msg ERR_DEADLOCK)"
  fi
  if [ "$password_auth" = "no" ] && [ "$key_ok" != "y" ]; then
    die "$(msg ERR_PASSWORD_NO_KEY)"
  fi
  if [ "$user" = "root" ] && [ "$password_auth" = "no" ] && [ "$key_ok" != "y" ]; then
    die "$(msg ERR_ROOT_NO_KEY)"
  fi
  if [ "$port_setting" != "$SSH_PORT" ]; then
    warn "$(msg WARN_PORT_MISMATCH) ($port_setting vs $SSH_PORT)"
  fi

  insecure_options=0
  if printf '%s\n' "$sshd_T_out" | awk 'BEGIN { found = 0 } tolower($1)=="x11forwarding" && tolower($2)=="yes" { found = 1; exit } END { exit !found }' 2>/dev/null; then
    warn "$(msg WARN_X11_FORWARDING)"
    insecure_options=$((insecure_options + 1))
  fi
  if printf '%s\n' "$sshd_T_out" | awk 'BEGIN { found = 0 } tolower($1)=="permitemptypasswords" && tolower($2)=="yes" { found = 1; exit } END { exit !found }' 2>/dev/null; then
    warn "$(msg WARN_EMPTY_PASSWORDS)"
    insecure_options=$((insecure_options + 1))
  fi
  [ "$insecure_options" -gt 0 ] && warn "$(msg WARN_INSECURE_OPTIONS) $insecure_options"

  return 0
}

# =========================================================
# Entry
# =========================================================
[ "$(id -u)" -eq 0 ] || { msg MUST_ROOT; exit 1; }

# [v4.7.0] Redact sensitive argv (URLs may carry tokens; raw keys are large) before audit.
sanitized_args=""
for _a in "$@"; do
  case "$_a" in
    --key-raw=*) sanitized_args="$sanitized_args --key-raw=<redacted>" ;;
    --key-url=*) sanitized_args="$sanitized_args --key-url=<redacted>" ;;
    --key-gh=*)  sanitized_args="$sanitized_args --key-gh=<redacted>" ;;
    *)           sanitized_args="$sanitized_args $_a" ;;
  esac
done
audit_log "START" "Script started with args:$sanitized_args"
unset sanitized_args _a

if command -v clear >/dev/null 2>&1; then clear; fi
echo "================================================="
msg BANNER
echo "================================================="
[ "$STRICT_MODE" = "y" ] && msg STRICT_ON

preflight_checks

# Phase 1: Input
if [ -n "$ARG_USER" ]; then
  TARGET_USER="$ARG_USER"
  validate_username "$TARGET_USER" || die "$(msg ERR_USER_INV): $TARGET_USER"
  printf "%s%s\n" "$(msg AUTO_SKIP)" "$TARGET_USER"
else
  while :; do
    printf "%s%s): " "$(msg ASK_USER)" "$DEFAULT_USER"
    read -r TARGET_USER
    [ -z "$TARGET_USER" ] && TARGET_USER="$DEFAULT_USER"
    validate_username "$TARGET_USER" && break
    msg ERR_USER_INV
  done
fi

if [ -n "$ARG_PORT" ]; then
  case "$ARG_PORT" in
    22) PORT_OPT="1"; SSH_PORT="22" ;;
    random) PORT_OPT="2"; SSH_PORT="22" ;;
    *)
      if ! validate_port "$ARG_PORT"; then
        die "$(msg PORT_ERR): $ARG_PORT"
      fi
      if is_hard_reserved "$ARG_PORT"; then
        die "$(msg PORT_RES): $ARG_PORT"
      fi
      if is_k8s_nodeport "$ARG_PORT"; then
        warn "$(msg PORT_K8S)"
      fi
      PORT_OPT="3"; SSH_PORT="$ARG_PORT"
      ;;
  esac
  printf "%s%s\n" "$(msg AUTO_SKIP)" "$ARG_PORT (Mode $PORT_OPT)"
else
  echo ""
  msg ASK_PORT_T; msg OPT_PORT_1; msg OPT_PORT_2; msg OPT_PORT_3
  printf "%s" "$(msg SELECT)"; read -r PORT_OPT
  [ -z "$PORT_OPT" ] && PORT_OPT="1"
  SSH_PORT="22"
  if [ "$PORT_OPT" = "3" ]; then
    while :; do
      printf "%s" "$(msg INPUT_PORT)"
      read -r MANUAL_PORT
      printf '%s\n' "$MANUAL_PORT" | grep -Eq '^[0-9]+$' || { msg PORT_ERR; continue; }
      [ "$MANUAL_PORT" -ge 1024 ] 2>/dev/null && [ "$MANUAL_PORT" -le 65535 ] 2>/dev/null || { msg PORT_ERR; continue; }
      if is_hard_reserved "$MANUAL_PORT"; then
        msg PORT_RES
        continue
      elif is_k8s_nodeport "$MANUAL_PORT"; then
        msg PORT_K8S
        printf "%s" "$(msg ASK_SURE)"
        read -r force_port
        [ "${force_port:-n}" = "y" ] || continue
      fi
      SSH_PORT="$MANUAL_PORT"
      break
    done
  fi
fi

if [ -n "$ARG_KEY_TYPE" ]; then
  KEY_OPT="auto"; KEY_TYPE="$ARG_KEY_TYPE"; KEY_VAL="$ARG_KEY_VAL"
  # [v4.7.1 FIX-M1] Don't echo raw key material or URLs (may contain tokens)
  # to stdout — the audit log is already sanitized but stdout/scrollback
  # captures (tee, screen, tmux) bypass that.
  case "$KEY_TYPE" in
    raw) printf "%s%s\n" "$(msg AUTO_SKIP)" "$KEY_TYPE (<redacted>)" ;;
    url) printf "%s%s\n" "$(msg AUTO_SKIP)" "$KEY_TYPE (<redacted>)" ;;
    *)   printf "%s%s\n" "$(msg AUTO_SKIP)" "$KEY_TYPE ($KEY_VAL)" ;;
  esac
else
  echo ""
  msg ASK_KEY_T; msg OPT_KEY_1; msg OPT_KEY_2; msg OPT_KEY_3
  printf "%s" "$(msg SELECT)"; read -r KEY_OPT
  case "$KEY_OPT" in
    1) KEY_TYPE="gh";  printf "%s" "$(msg INPUT_GH)"; read -r KEY_VAL ;;
    2) KEY_TYPE="url"; printf "%s" "$(msg INPUT_URL)"; read -r KEY_VAL ;;
    3)
      # [v4.7.3 FIX-MED] Build $raw with a REAL newline, not literal '\n' that
      # later needs printf %b — which would interpret any \c the user typed
      # and silently truncate the result.
      KEY_TYPE="raw"
      msg INPUT_RAW
      raw=""
      __nl='
'
      while IFS= read -r l; do
        [ -z "$l" ] && break
        raw="${raw}${l}${__nl}"
      done
      KEY_VAL="$raw"
      unset raw l __nl
      ;;
    *) die "Invalid Option" ;;
  esac
fi

if [ -n "$ARG_UPDATE" ]; then DO_UPDATE="$ARG_UPDATE"; printf "%s%s\n" "$(msg AUTO_SKIP)" "Update=$DO_UPDATE"; else printf "%s" "$(msg ASK_UPD)"; read -r DO_UPDATE; [ -z "$DO_UPDATE" ] && DO_UPDATE="n"; fi
if [ -n "$ARG_BBR" ]; then DO_BBR="$ARG_BBR"; printf "%s%s\n" "$(msg AUTO_SKIP)" "BBR=$DO_BBR"; else printf "%s" "$(msg ASK_BBR)"; read -r DO_BBR; [ -z "$DO_BBR" ] && DO_BBR="n"; fi

# Phase 2: Confirm
if [ "$AUTO_CONFIRM" = "y" ]; then
  echo ""; info "Auto-Confirm: Skipping interactive confirmation."
else
  echo ""
  msg CONFIRM_T
  echo "$(msg C_USER)$TARGET_USER"
  echo "$(msg C_PORT)$SSH_PORT (Mode: $PORT_OPT)"
  echo "$(msg C_KEY)$KEY_TYPE"
  echo "$(msg C_UPD)$DO_UPDATE"
  echo "$(msg C_BBR)$DO_BBR"
  [ "$PORT_OPT" != "1" ] && msg WARN_FW
  printf "%s" "$(msg ASK_SURE)"
  read -r CONFIRM
  [ "${CONFIRM:-n}" = "y" ] || die "$(msg CANCEL)"
fi

# Phase 3: Execute
msg AUDIT_START
setup_rollback
backup_config_persistent || true

info "$(msg I_INSTALL)"
ensure_ssh_server

detect_openssh_version
detect_kbd_interactive_support
info "OpenSSH Version: ${OPENSSH_VER_MAJOR}.${OPENSSH_VER_MINOR}"

install_pkg_try curl >/dev/null 2>&1 || true
install_pkg_try wget >/dev/null 2>&1 || true

# === [新增] 补充常用管理工具 ===
if ! command -v sudo >/dev/null 2>&1; then
  info "Installing missing dependency: sudo..."
  install_pkg sudo >/dev/null 2>&1 || true
fi

if ! command -v hostname >/dev/null 2>&1; then
  # Debian/Ubuntu 下 hostname 命令通常在 hostname 包或 net-tools 中
  install_pkg hostname >/dev/null 2>&1 || true
fi

if [ "$DO_UPDATE" = "y" ]; then info "$(msg I_UPD)"; update_system; fi
if [ "$DO_BBR" = "y" ]; then info "$(msg I_BBR)"; enable_bbr; fi

if [ "$PORT_OPT" = "2" ]; then
  p="$(pick_random_port 2>/dev/null || true)"
  if [ -n "$p" ]; then
    SSH_PORT="$p"
    info "Random Port: $SSH_PORT"
  else
    [ "$STRICT_MODE" = "y" ] && die "STRICT: Random port failed"
    warn "Random port failed, fallback to 22"
    SSH_PORT="22"
  fi
fi

# [v4.7.3 FIX-H5] Always run stale-rule cleanup — including when this run
# REVERTS to port 22. Otherwise a sequence of `--port=2222` then later
# `--port=22` would leak the 2222 rule.
remove_stale_firewall_port "$SSH_PORT"

if [ "$SSH_PORT" != "22" ]; then
  allow_firewall_port "$SSH_PORT"
  handle_selinux "$SSH_PORT"
  # [v4.7.4] Re-record state AFTER handle_selinux so the persisted file
  # also reflects SELinux ownership. allow_firewall_port already called
  # record_last_applied with the firewall backend; this overwrites with the
  # complete picture including SELINUX_PORT.
  if [ "$SELINUX_LABEL_APPLIED" = "y" ]; then
    # Re-read the firewall backend just persisted (or fall back to empty).
    if [ -f "$LAST_APPLIED_FILE" ]; then
      __recorded_fw=$(awk -F= '$1=="FIREWALL"{print $2; exit}' "$LAST_APPLIED_FILE" 2>/dev/null)
      case "$__recorded_fw" in
        *:*) __recorded_be="${__recorded_fw%%:*}" ;;
        *)   __recorded_be="" ;;
      esac
      # [v4.7.5] Pass SELINUX_LABEL_OWNED_BY_RUN as 4th arg so the persisted
      # file distinguishes "we own this and may delete on next run" from
      # "label pre-existed independently, don't touch on next run".
      record_last_applied "$SSH_PORT" "$__recorded_be" "y" "$SELINUX_LABEL_OWNED_BY_RUN"
      unset __recorded_fw __recorded_be
    else
      record_last_applied "$SSH_PORT" "" "y" "$SELINUX_LABEL_OWNED_BY_RUN"
    fi
  fi
else
  # [v4.7.3 + v4.7.4] When the operator reverts to port 22, clear the
  # last-applied state. The stale-cleanup above already removed the prior
  # firewall + SELinux state for the OLD port. Nothing to remember.
  if [ -f "$LAST_APPLIED_FILE" ]; then
    rm -f "$LAST_APPLIED_FILE" 2>/dev/null || true
    audit_log "LAST_APPLIED_CLEARED" "reverting to port 22"
  fi
fi

safe_ensure_user "$TARGET_USER" || die "User setup failed"

root_home=$(get_user_home root)
[ -s "$root_home/.ssh/authorized_keys" ] && ROOT_KEY_PRESENT="y" || ROOT_KEY_PRESENT="n"

KEY_OK="n"
KEY_DATA="$(fetch_keys "$KEY_TYPE" "$KEY_VAL" 2>/dev/null || true)"
if [ -n "$KEY_DATA" ] && deploy_keys "$TARGET_USER" "$KEY_DATA"; then
  KEY_OK="y"
  info "$(msg I_KEY_OK)"
else
  [ "$STRICT_MODE" = "y" ] && die "STRICT: Key deploy failed"
  warn "$(msg W_KEY_FAIL)"
fi

# [v4.7.0 / CRIT] Apply password policy now that KEY_OK is known.
# [v4.7.1] Pass USER_WAS_CREATED so pre-existing admin passwords are preserved.
# [v4.7.2] Pass SUDO_DEPLOYED so new accounts that lack sudo stay locked
#          (prevents passwordless+no-sudo combo).
finalize_user_password_policy "$TARGET_USER" "$KEY_OK" "$USER_WAS_CREATED" "$SUDO_DEPLOYED"

if has_global_ipv6; then
  IPV6_ENABLED="y"
  info "$(msg IPV6_CFG)"
else
  IPV6_ENABLED="n"
fi

compute_crypto_lines
if [ "$CRYPTO_MODE" = "skip" ]; then
  info "$(msg INFO_OLD_SSH_SKIP_ALGO)"
elif [ "$CRYPTO_MODE" = "fallback" ]; then
  warn "$(msg COMPAT_WARN)"
fi

info "$(msg I_BACKUP)$SSH_CONF"
cleanup_sshd_config_d
remove_managed_block
sanitize_sshd_config

tmp="$TMP_DIR/sshd_block_final"
build_block "$tmp"

install_managed_block "$tmp"

# [v4.7.0 / MED] protect_sshd_service is a safety feature — it must run
# regardless of whether we'll restart sshd in this invocation. The flag was
# only ever supposed to skip the live restart + connection tests.
protect_sshd_service

if ! sshd -t -f "$SSH_CONF" 2>>"$LOG_FILE"; then die "$(msg E_SSHD_CHK)"; fi
validate_ssh_config_comprehensive "$SSH_CONF" "$TARGET_USER" "$KEY_OK"

# [SEC-FIX] Handle --delay-restart properly: skip restart and tests
if [ "$ARG_DELAY_RESTART" = "y" ]; then
  warn "$(msg DELAY_RESTART_MSG)"
  # [v4.7.3 FIX-MED] Surface the systemd override status — we wrote it but
  # didn't restart, so the operator should know the protection (Restart=,
  # OOMScoreAdjust=) only takes effect on next sshd start.
  if command -v systemctl >/dev/null 2>&1 && [ -f /etc/systemd/system/sshd.service.d/override.conf ]; then
    info "systemd override written at /etc/systemd/system/sshd.service.d/override.conf — applies on next sshd restart"
  fi
  update_motd
  generate_health_report
  
  trap - INT TERM EXIT HUP
  cleanup_state
  cleanup_locks
  rm -rf "$TMP_DIR" 2>/dev/null || true
  
  print_final_summary
  audit_log "DONE" "Completed (delay-restart). user=$TARGET_USER port=$SSH_PORT key_ok=$KEY_OK"
  exit 0
fi

if ! restart_sshd; then
  die "$(msg E_RESTART)"
fi

grep -Eq "^[[:space:]]*Port[[:space:]]+$SSH_PORT([[:space:]]|\$)" "$SSH_CONF" 2>/dev/null || die "$(msg E_GREP_FAIL)"
verify_sshd_listening "$SSH_PORT" || die "$(msg W_LISTEN_FAIL)"
enhanced_ssh_test "$SSH_PORT" "$TARGET_USER" || die "$(msg TEST_FAIL)"

update_motd
generate_health_report

trap - INT TERM EXIT HUP
cleanup_state
cleanup_locks
rm -rf "$TMP_DIR" 2>/dev/null || true

print_final_summary
audit_log "DONE" "Completed successfully. user=$TARGET_USER port=$SSH_PORT key_ok=$KEY_OK"
exit 0
