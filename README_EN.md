# Linux Server Init & SSH Hardening Script

<p align="center">
  <strong>
    <a href="README.md">🇨🇳 中文文档</a> | 🇺🇸 English
  </strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Shell-POSIX_sh-blue?style=flat-square" alt="POSIX Shell">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/github/v/release/247like/linux-ssh-init-sh?style=flat-square" alt="Release">
  <img src="https://img.shields.io/github/stars/247like/linux-ssh-init-sh?style=flat-square" alt="Stars">
</p>

---

A production-ready, POSIX-compliant shell script designed to initialize Linux servers and harden SSH security in minutes.

It safely handles **SSH key deployment**, **port changing**, **user creation**, **TCP BBR enablement**, and **system updates**, while ensuring compatibility across Debian, Ubuntu, CentOS, RHEL, and Alpine Linux.

### ✨ Key Features

* **Universal Compatibility**: Works flawlessly on **Debian 10/11/12**, **Ubuntu**, **CentOS 7/8/9**, **Alma/Rocky**, and **Alpine Linux**.
* **POSIX Compliant**: Written in pure `/bin/sh`. No `bash` dependency. Runs perfectly on `dash` (Debian) and `ash` (Alpine/Busybox).
* **Safety Architecture**:
    * **Managed Config Block**: Inserts configuration at the **top** of `sshd_config` to strictly override vendor defaults (bypasses the Debian 12 `Include` trap).
    * **Atomic Verification**: Validates config with `sshd -t` before restarting. Automatically rolls back on failure to prevent downtime.
    * **Anti-Lockout**: If SSH keys fail to deploy, it **will not** disable password login, ensuring you don't lose access.
    * **Firewall Awareness**: Automatically detects and configures `ufw` or `firewalld` if port is changed.
* **Automation Friendly**:
    * Supports **Headless Mode**, allowing zero-interaction unattended installation via command line arguments.
    * **Random High Port**: Automatically generates a random port between 20000-60000 and checks for availability.

### 🚀 Quick Start

Run the following command as **root**.

#### 1. Interactive Run (Recommended)
```bash
curl -fsSL https://raw.githubusercontent.com/247like/linux-ssh-init-sh/main/init.sh -o init.sh && chmod +x init.sh && ./init.sh
```

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
| **User/Port** | `--user=root` | Specify login user (root or username) |
| | `--port=22` | Keep default port 22 |
| | `--port=random` | Generate random high port (20000-60000) |
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
| **Key Failure** | If key download fails, script **keeps Password Auth enabled** and warns you.<br>👉 *Result: Server reachable but less secure.* | Script **exits immediately**. No changes applied.<br>👉 *Result: Deployment aborted, state unchanged.* |
| **Port Failure** | If random port fails, it falls back to **Port 22**. | Script **exits immediately**. |
| **Use Case** | Manual setup, unstable networks. | CI/CD pipelines, high-security requirements. |

### 🛠️ Execution Details

1.  **Dependency Check**: Auto-detects package manager (`apt`, `yum`, `apk`) and installs dependencies (`curl`, `sudo`, `openssh-server`).
2.  **User Setup**: Creates the specified user (if not root) and grants password-less `sudo` privileges.
3.  **Key Deployment**: Deploys SSH public keys, fixes `.ssh` permissions, and supports deduplication.
4.  **SSH Hardening**:
    * Backs up `sshd_config`.
    * Cleans up old script blocks.
    * Inserts a new configuration block at the **top** of the file (Disable password, Change port, etc.) to ensure highest priority.
5.  **Finalization**: Validates config syntax, restarts SSH service, and applies BBR/Updates if selected.

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
