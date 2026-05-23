# Linux Server Init & SSH Hardening Script

[![Test Matrix](https://github.com/247like/linux-ssh-init-sh/actions/workflows/test.yml/badge.svg)](https://github.com/247like/linux-ssh-init-sh/actions/workflows/test.yml)
![POSIX Shell](https://img.shields.io/badge/Shell-POSIX_sh-blue?style=flat-square)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Release](https://img.shields.io/github/v/release/247like/linux-ssh-init-sh?style=flat-square)](https://github.com/247like/linux-ssh-init-sh/releases)
[![Stars](https://img.shields.io/github/stars/247like/linux-ssh-init-sh?style=flat-square)](https://github.com/247like/linux-ssh-init-sh/stargazers)

[![中文文档](https://img.shields.io/badge/中文-Chinese-blue)](README.md) [![English](https://img.shields.io/badge/English-EN-blue)](README_EN.md)

---

A production-ready, POSIX-compliant shell script designed to initialize Linux servers and harden SSH security in minutes.

It safely handles **SSH key deployment**, **port changing**, **user creation**, **TCP BBR enablement**, and **system updates**, while ensuring compatibility across Debian, Ubuntu, CentOS, RHEL, and Alpine Linux.

### ✨ Key Features

* **Universal Compatibility**: Works flawlessly on **Debian**, **Ubuntu**, **CentOS/RHEL**, **Alma/Rocky**, and **Alpine Linux**.
* **POSIX Compliant**: Written in pure `/bin/sh`. No `bash` dependency. Runs perfectly on `dash` (Debian) and `ash` (Alpine/Busybox).
* **Security Architecture (Fortress Pro)**:
    * **Managed Config Block**: Inserts configuration at the **top** of `sshd_config` to strictly override vendor defaults (bypasses the Debian 12 `Include` trap).
    * **Auto-Rollback**: If SSHD validation fails, port is not listening, or connection test fails during execution, the script **automatically reverts** all system changes.
    * **Service Protection (Anti-Kill)**: Adds a systemd `override.conf` to prevent OOM kills and ensures SSHD restarts automatically on failure.
    * **Deadlock Prevention**: Intelligently detects authentication states to prevent "Password Disabled + No Key" lockouts.
* **Automation Friendly**:
    * Supports **Headless Mode** allowing zero-interaction unattended installation.
    * **Audit & Reporting**: Automatically generates detailed operation audit logs and system health reports.

### 🚀 Quick Start

Run the following command as **root**.

#### 1. Interactive Run (Recommended)
```bash
curl -fsSL https://raw.githubusercontent.com/247like/linux-ssh-init-sh/main/init.sh -o init.sh && chmod +x init.sh && ./init.sh
```

> 🛡️ **Audit tip**: this script modifies SSH config — prefer the "download then run" form above so you can inspect `init.sh` before executing. Avoid `curl … | sh`.

#### 2. Force English UI
```bash
./init.sh --lang=en
```

### 🤖 Automation (Headless Mode)

Suitable for CI/CD pipelines or bulk provisioning. Use command line arguments to pass configurations and `--yes` to skip confirmation.

#### Full Automatic Example
*(Configure Root user, random port, fetch key from GitHub, enable BBR, update system, auto-confirm)*

```bash
curl -fsSL https://raw.githubusercontent.com/247like/linux-ssh-init-sh/main/init.sh | sh -s -- \
    --user=root \
    --port=random \
    --key-gh=247like \
    --bbr \
    --update \
    --strict \
    --yes
```

#### Semi-Automatic Example
*(Specify key URL, choose other options manually)*

```bash
./init.sh --key-url=https://my-server.com/id_ed25519.pub
```

### ⚙️ Arguments

The script supports rich command-line arguments to control its behavior:

| Category | Argument | Description |
| :--- | :--- | :--- |
| **Control** | `--lang=en` | Force English UI |
| | `--yes` | **Auto Confirm**: Skip the final "Proceed?" prompt |
| | `--strict` | **Strict Mode**: Exit immediately on error (see below) |
| | `--delay-restart` | **Delay Restart**: Apply config but do not restart SSHD immediately |
| | `--no-ip-probe` | Skip the external IP lookup (`api.ipify.org`) — for offline/air-gapped hosts |
| | `-V / --version` | Print version and exit |
| | `-h / --help` | Show full help |
| **User/Port** | `--user=root` | Specify login user (root or username) |
| | `--port=22` | Keep default port 22 |
| | `--port=random` | Generate random high port (49152-65535) |
| | `--port=2222` | Specify a specific port number |
| **Keys** | `--key-gh=username` | Fetch public key from GitHub |
| | `--key-url=url` | Download public key from URL |
| | `--key-raw="ssh-..."` | Pass public key string directly |
| **System** | `--update` | Enable system package update |
| | `--no-update` | Skip system update |
| | `--bbr` | Enable TCP BBR congestion control |
| | `--no-bbr` | Disable BBR |

### ⚙️ Normal Mode vs. Strict Mode

| Feature | Normal Mode (Default) | Strict Mode (`--strict`) |
| :--- | :--- | :--- |
| **Philosophy** | **"Don't Lockout"** (Best Effort) | **"Compliance First"** (Zero Tolerance) |
| **Key Failure** | Password auth remains enabled with a warning, and any newly-created user **stays locked** (v4.7.0+).<br>👉 *Existing root/password users can still log in to repair; the new account never becomes passwordless+open.* | Script **exits immediately**. |
| **Existing-user password** | v4.7.1+: the script **does NOT clear** an existing user's password; `passwd -d` runs only for accounts newly created in this run | Same |
| **Port Failure** | Falls back to **port 22**. | Script **exits immediately**. |
| **HTTP key URL** | Warn-and-continue | Reject `http://`, require `https://` |
| **Firewall rule add failed** | Warn only | Warn + log (non-22 ports) |

### 📦 Requirements

* **Privileges**: must run as `root`
* **Mandatory commands**: `cat / grep / awk / sed / cp / mv / chmod / chown / mkdir / rm / id`
* **Recommended commands** (auto-installed if missing): `curl` or `wget`, `sudo`, `openssh-server`, `ss` or `netstat`, `nc`, `base64`, `ssh-keygen`
* **Verified distros** (full CI matrix):
  * Debian 11 / 12
  * Ubuntu 22.04 / 24.04
  * Alpine (latest)
  * AlmaLinux 9 / Rocky Linux 9 / CentOS Stream 9
  * CentOS 7 (EOL — best effort, allow-failure in CI)

### 📁 Files the script creates / modifies

| Path | Purpose |
| :--- | :--- |
| `/etc/ssh/sshd_config` | Managed block injected; conflicting drop-ins renamed `*.bak_server_init` |
| `/etc/ssh/sshd_config.d/*.conf` | Conflicting drop-ins backed up/disabled |
| `/etc/sudoers.d/server-init-<user>` | Stable filename (v4.7.0+) — delete to revoke |
| `/etc/systemd/system/sshd.service.d/override.conf` | Anti-kill / restart policy |
| `/etc/profile.d/z99-ssh-init-banner.sh` | Login banner |
| `/etc/motd` + `/etc/motd.bak` | Strips stale server-init lines; first run preserves real `.bak` |
| `/etc/sysctl.conf` | BBR lines appended when `--bbr` is enabled |
| **Firewall rules** (ufw/firewalld/iptables/ip6tables) | Opens TCP port when `--port != 22`; rollback only undoes the backend the script used |
| **SELinux port labels** | When system is Enforcing, applies `semanage port -a -t ssh_port_t`; `-m` (modify) path cannot be cleanly rolled back |
| `/home/<user>/.ssh/authorized_keys` | Deployed keys; symlinks rejected; home owner verified (v4.7.3) |
| `/var/log/server-init.log` | Runtime log |
| `/var/log/server-init-audit.log` | Audit trail (redacts `--key-raw` / `--key-url`) |
| `/var/log/server-init-health.log` | Post-run snapshot |
| `/var/backups/ssh-config/<TS>/` | Persistent backup + `restore.sh` + `checksums.sha256` |
| `/var/lib/server-init/last-applied` | (v4.7.3+) records the previous successful port + firewall backend; v4.7.4 also records `SELINUX_PORT=N` so port-change runs clean the prior SELinux label; v4.7.5 adds `SELINUX_OWNED=y/n` distinguishing "label this script installed" from "label that pre-existed" — only the former is cleaned across runs |
| `/run/server-init/script.lock/` or `/var/lib/server-init/script.lock/` | (v4.7.6+) Script-level mutex directory (holds PID file). Auto-removed on normal exit; if the script was `kill -9`'d the dir may linger — the next start auto-detects whether the holder PID is still alive and reclaims if not |
| `/run/server-init/last-artifacts-<UID>` or `/var/lib/server-init/last-artifacts-<UID>` | (v4.7.6+) Artifact mirror appended during run; cleared on normal exit. If the script crashed, the next start surfaces this list to alert the operator to stranded mutations |

### 🔁 Idempotency / re-runs

* The managed block is **removed and re-inserted** on every run — no duplicate stacking
* Sudoers file uses a stable per-user name; re-runs overwrite instead of accumulating
* **Upgrading from < v4.7.0**: older versions left timestamped sudoers files (`server-init-<user>-YYYYMMDD...`). v4.7.1 added auto-cleanup on the next run; **v4.7.2 narrows the match to digits-only suffixes** so admin-created files like `server-init-<user>-special-policy` are preserved and sibling accounts that share a hyphen-prefix (e.g. `admin` vs `admin-bot`) cannot be collaterally cleaned. Each removal is recorded in audit log as `LEGACY_SUDOERS_REMOVED`
* Backups rotate by timestamp; the **10 most recent** are retained, older ones pruned automatically

### 🚪 Exit codes

| Code | Meaning |
| :---: | :--- |
| 0 | Success |
| 1 | Generic error / user cancel / config failure |
| 130 | `SIGINT` (Ctrl-C) |
| 143 | `SIGTERM` |
| 129 | `SIGHUP` |
| ≠ 0 (mid-deploy) | Triggers automatic rollback — inspect `/var/log/server-init.log` + `audit.log` |

> Note: Ctrl-C during the **confirmation prompt** does NOT enter the rollback path (no destructive changes have happened yet).

### 📂 Logs & Audit

After execution, the following files are generated for troubleshooting and auditing:

> 📋 **Log-rotation recommendation**: the three log files below are append-only with no built-in rotation. For frequent runs (CI / fleet installs) drop in a logrotate config:
> ```
> # /etc/logrotate.d/server-init
> /var/log/server-init*.log {
>     weekly
>     rotate 12
>     compress
>     delaycompress
>     missingok
>     notifempty
>     create 0600 root root
> }
> ```

* **Run Log**: `/var/log/server-init.log` (Detailed debug information)
* **Audit Log**: `/var/log/server-init-audit.log` (Records key actions, timestamps, and operators)
  * Action categories (**recommended-to-alert in bold**):
    * **Lifecycle**: `START` / `DONE` / **`ROLLBACK`** / **`RESTART_REFUSED`**
    * **Accounts**: `USER_CREATED` / `PASSWORD_CLEARED` / `KEYS_DEPLOYED` / **`ACCOUNT_KEPT_LOCKED`** / **`USER_REMOVE_FAILED`**
    * **Sudo**: `SUDOERS_WRITTEN` / **`SUDO_FAIL`** / `LEGACY_SUDOERS_REMOVED`
    * **System config**: `MANAGED_BLOCK_INSTALLED` / `DROPIN_RENAMED` / `SYSTEMD_OVERRIDE_WRITTEN` / `MOTD_BANNER_WRITTEN` / `BBR_ENABLED` / `SYSTEM_UPDATE_START` / `SYSTEM_UPDATE_DONE`
    * **Firewall**: `FIREWALL_OPENED` / `FIREWALL_NOOP` / `STALE_FIREWALL_REMOVED` / `LAST_APPLIED_CLEARED`
    * **SELinux**: `SELINUX_PORT_ADDED` / `SELINUX_PORT_NOOP` / `SELINUX_PORT_MODIFIED` / **`SELINUX_PORT_FAIL`** / `STALE_SELINUX_REMOVED` / **`STALE_SELINUX_REMOVE_FAILED`** / `STALE_SELINUX_KEPT` / `STALE_SELINUX_SKIP`
    * **Incomplete-rollback alerts** (high-priority): **`ROLLBACK_RM_FAILED`** / **`ROLLBACK_MOTD_FAILED`** / **`ROLLBACK_MOTD_BAK_MISSING`** / **`STRANDED_MUTATIONS_DETECTED`**
    * **Test / security**: `LOGIN_TEST_PASSED` / `LOGIN_TEST_INCONCLUSIVE` / `INSECURE_KEY_URL` / `KEY_FETCH_FAILED` / `DIRECT_SPAWN` / `DIRECT_SPAWN_REFUSED`
  * Stderr fallback format (when `/var/log` is unwritable): `AUDIT-FALLBACK <timestamp> ACTION=<name> DETAILS=<...>`
  * Designed for SIEM ingestion
* **Health Report**: `/var/log/server-init-health.log` (Snapshot of the final system configuration state)

### 🆘 Disaster Recovery & Restore

The script features a dual-layer safety mechanism: **Runtime Auto-Rollback** and **Persistent Backup Restore**.

If you cannot connect to your server via SSH after the script finishes (after seeing "DONE"), log in via your Cloud Provider's **VNC / Console** and use one of the following methods.

#### Method A: One-Click Restore Script (Recommended)

Each run creates a backup with a **SHA256 checksums file**. `restore.sh` verifies `checksums.sha256` before applying anything — a tampered backup is rejected.

1.  Find the latest backup directory:
    ```bash
    ls -ld /var/backups/ssh-config/*
    ```
2.  Enter the directory and run the restore script:
    ```bash
    cd /var/backups/ssh-config/<TIMESTAMP>/
    sh restore.sh
    ```
    `restore.sh` will: ① verify checksums → ② restore `sshd_config` + `sshd_config.d/` → ③ run `sshd -t` → ④ restart sshd. Any failure aborts with a non-zero exit code.

    **Override**: if `checksums.sha256` is missing or `sha256sum` is unavailable, `restore.sh` **REFUSES** to run (defends against restoring a tampered backup). If you're certain the backup is good and need to bypass:
    ```bash
    FORCE=1 sh restore.sh
    ```
    Use only when you **trust the backup contents** (e.g. you manually pruned `checksums.sha256` yourself).

> ⚠ `restore.sh` only restores **`sshd_config` and its drop-ins**. Users / sudoers / systemd overrides / firewall rules created during the run are best undone by the **runtime auto-rollback** (which fires on any failure during the script run); see the "Files the script creates / modifies" table above for manual cleanup.

#### Method B: Manual Restore

If `restore.sh` is unavailable, copy files by hand:

```bash
# 1. Verify (recommended)
cd /var/backups/ssh-config/<TIMESTAMP>/ && sha256sum -c checksums.sha256

# 2. Overwrite configuration
cp /var/backups/ssh-config/<TIMESTAMP>/sshd_config /etc/ssh/sshd_config

# 3. Restart service
systemctl restart sshd || service sshd restart
```

---

### ⚠️ Disclaimer

This script modifies critical system configurations (SSH). While it includes multiple safety checks and automatic rollback mechanisms, **please ensure you have an alternative access method** (such as a VNC/KVM Console) to your server to prevent lockout in case of network interruptions or unexpected configuration errors.

### 📄 License

This project is released under the [MIT License](LICENSE).

---

<div align="center">

If you found this tool helpful, please give it a ⭐ Star!

[Report Bug](https://github.com/247like/linux-ssh-init-sh/issues) · [Request Feature](https://github.com/247like/linux-ssh-init-sh/issues)

</div>
