# Linux 服务器初始化与 SSH 安全加固

[![Test Matrix](https://github.com/247like/linux-ssh-init-sh/actions/workflows/test.yml/badge.svg)](https://github.com/247like/linux-ssh-init-sh/actions/workflows/test.yml)
![POSIX Shell](https://img.shields.io/badge/Shell-POSIX_sh-blue?style=flat-square)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Release](https://img.shields.io/github/v/release/247like/linux-ssh-init-sh?style=flat-square)](https://github.com/247like/linux-ssh-init-sh/releases)
[![Stars](https://img.shields.io/github/stars/247like/linux-ssh-init-sh?style=flat-square)](https://github.com/247like/linux-ssh-init-sh/stargazers)

[![中文文档](https://img.shields.io/badge/中文-Chinese-blue)](README.md) [![English](https://img.shields.io/badge/English-EN-blue)](README_EN.md)

---

一个生产就绪、符合 POSIX 标准的 Shell 脚本，用于 Linux 服务器的一键初始化与 SSH 安全加固。

该脚本可自动完成 **SSH 密钥配置**、**修改端口**、**创建用户**、**开启 BBR** 以及 **系统更新**，并完美兼容 Debian, Ubuntu, CentOS, RHEL 以及 Alpine Linux。

### ✨ 核心特性

* **全平台兼容**: 完美支持 **Debian**, **Ubuntu**, **CentOS/RHEL**, **Alma/Rocky**, 以及 **Alpine Linux**。
* **POSIX 标准**: 纯 `/bin/sh` 编写，无需安装 `bash`。在 `dash` (Debian) 和 `ash` (Alpine/Busybox) 上稳定运行。
* **安全架构 (Fortress Pro)**:
    * **托管配置块**: 使用 `# BEGIN SERVER-INIT MANAGED BLOCK` 头部插入配置，确保优先级最高，不受 `Include` 指令干扰。
    * **自动回滚 (Auto-Rollback)**: 运行时若发生 SSHD 校验失败、端口未监听或连接测试失败，自动还原系统状态。
    * **进程防杀 (Anti-Kill)**: 为 SSHD 服务添加 systemd `override.conf`，防止 OOM 误杀并配置自动重启。
    * **防失联死锁检测**: 智能检测认证方式，防止出现“既禁用密码又未配好密钥”的死锁。
* **自动化友好**:
    * 支持 **无头模式 (Headless)**，通过命令行参数实现零交互无人值守安装。
    * **审计与报告**: 自动生成详细的操作审计日志与系统健康检查报告。

### 🚀 快速开始

请以 **root** 身份运行。

#### 1. 交互式运行 (推荐)
```bash
curl -fsSL https://raw.githubusercontent.com/247like/linux-ssh-init-sh/main/init.sh -o init.sh && chmod +x init.sh && ./init.sh
```

> 🛡️ **审计建议**：脚本会修改 SSH 配置，建议先下载到本地、查看内容、再执行 (上面这条命令就是 "先下载、再执行" 的写法，请勿改为 `curl ... | sh`)。

#### 2. 强制使用英文界面
```bash
./init.sh --lang=en
```

### 🤖 自动化部署 (无头模式)

适用于 CI/CD 或批量装机场景。使用命令行参数传递配置，配合 `--yes` 跳过确认。

#### 全自动运行示例
*(配置 Root 用户、随机端口、从 GitHub 拉取公钥、开启 BBR、更新系统、自动确认)*

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

#### 半自动示例
*(指定公钥来源，其他选项手动选择)*

```bash
./init.sh --key-url=https://my-server.com/id_ed25519.pub
```

### ⚙️ 参数详解

脚本支持丰富的命令行参数来控制行为：

| 参数类别 | 参数 | 说明 |
| :--- | :--- | :--- |
| **基础控制** | `--lang=en` | 强制使用英文界面 |
| | `--yes` | **自动确认**：跳过脚本最后的 "确认执行?" 询问 |
| | `--strict` | **严格模式**：遇到任何错误立即退出 (详见下方) |
| | `--delay-restart` | **延迟重启**：修改配置但不重启 SSH 服务 (适用于特殊环境) |
| | `--no-ip-probe` | 跳过外网 IP 探测 (`api.ipify.org`)，适用于离线/隔离环境 |
| | `-V / --version` | 打印版本并退出 |
| | `-h / --help` | 显示完整帮助 |
| **用户与端口** | `--user=root` | 指定登录用户 (root 或普通用户名) |
| | `--port=22` | 保持默认 22 端口 |
| | `--port=random` | 生成随机高位端口 (49152-65535) |
| | `--port=2222` | 指定具体端口号 |
| **密钥来源** | `--key-gh=username` | 从 GitHub 用户拉取公钥 |
| | `--key-url=url` | 从指定 URL 下载公钥 |
| | `--key-raw="ssh-..."` | 直接传递公钥内容字符串 |
| **系统选项** | `--update` | 开启系统软件包更新 |
| | `--no-update` | 跳过系统更新 |
| | `--bbr` | 开启 TCP BBR 拥塞控制 |
| | `--no-bbr` | 不开启 BBR |

### ⚙️ 普通模式 vs 严格模式

| 场景 | 普通模式 (默认) | 严格模式 (`--strict`) |
| :--- | :--- | :--- |
| **设计理念** | **"优先保命"** (尽力而为) | **"优先合规"** (零容忍) |
| **公钥失败** | 托管块写入 `PasswordAuthentication yes`（保留密码登录通道），新建用户**保持锁定**（不会成为无密码可登录账号）。<br>👉 *结果：原有 root/密码用户仍能登录修补；新建用户因为账号锁定无法登录，操作员看到明确告警提示。* | 脚本**立即报错退出**，不修改任何配置。 |
| **既有用户密码** | v4.7.1 起：脚本**不再清除已存在用户的密码**，仅对新建账号执行 `passwd -d` | 同左 |
| **端口失败** | 若随机端口失败，回退使用 **端口 22**。 | 脚本**立即报错退出**。 |
| **HTTP 密钥 URL** | 仅警告并继续 | 拒绝 `http://`，要求 `https://` |
| **防火墙规则添加失败** | 仅警告 | 警告并打日志（非 22 端口时） |

### 📦 系统要求

* **权限**：必须以 `root` 身份运行
* **必备命令**：`cat / grep / awk / sed / cp / mv / chmod / chown / mkdir / rm / id`
* **建议命令** (脚本会自动补装)：`curl` 或 `wget`、`sudo`、`openssh-server`、`ss` 或 `netstat`、`nc`、`base64`、`ssh-keygen`
* **支持发行版** (CI 全量验证)：
  * Debian 11 / 12
  * Ubuntu 22.04 / 24.04
  * Alpine (latest)
  * AlmaLinux 9 / Rocky Linux 9 / CentOS Stream 9
  * CentOS 7 (EOL，仅尽力而为)

### 📁 脚本修改/创建的文件

| 路径 | 说明 |
| :--- | :--- |
| `/etc/ssh/sshd_config` | 注入托管配置块；旧值改名为 `*.bak_server_init` |
| `/etc/ssh/sshd_config.d/*.conf` | 冲突的 drop-in 自动备份重命名 |
| `/etc/sudoers.d/server-init-<user>` | 稳定文件名（v4.7.0 起），可直接删除以撤销 |
| `/etc/systemd/system/sshd.service.d/override.conf` | 防杀/自动重启 |
| `/etc/profile.d/z99-ssh-init-banner.sh` | 登录横幅 |
| `/etc/motd` + `/etc/motd.bak` | 清理旧的 server-init 行；首次创建 `.bak` 真备份 |
| `/etc/sysctl.conf` | 启用 BBR 时追加 `net.core.default_qdisc=fq` 与 `tcp_congestion_control=bbr` |
| **防火墙规则** (ufw/firewalld/iptables/ip6tables) | 仅在 `--port != 22` 时打开 TCP；rollback 仅撤销当前 backend 写入的规则 |
| **SELinux 端口标签** | 当系统处于 Enforcing 模式时通过 `semanage port -a` 加 `ssh_port_t` 标签；`-m`（modify）路径无法清晰回滚 |
| `/home/<user>/.ssh/authorized_keys` | 已部署的公钥；拒绝符号链接路径；校验家目录所有者 (v4.7.3) |
| `/var/log/server-init.log` | 运行日志 |
| `/var/log/server-init-audit.log` | 审计日志（已脱敏 `--key-raw=` / `--key-url=`） |
| `/var/log/server-init-health.log` | 健康快照 |
| `/var/backups/ssh-config/<TS>/` | 持久备份 + `restore.sh` + `checksums.sha256` |
| `/var/lib/server-init/last-applied` | (v4.7.3+) 记录上一次成功使用的端口/防火墙后端；v4.7.4 起额外记录 `SELINUX_PORT=N`；v4.7.5 起记录 `SELINUX_OWNED=y/n` 区分"本脚本安装的 label" 与"管理员预先存在的 label"，跨次运行只清理前者 |
| `/run/server-init/script.lock/` 或 `/var/lib/server-init/script.lock/` | (v4.7.6+) 脚本级互斥锁目录（含 PID 文件）。运行结束后自动清除；如果脚本被 `kill -9` 等异常终止可能遗留，下次启动会自动检测 PID 存活并回收 |
| `/run/server-init/last-artifacts-<UID>` 或 `/var/lib/server-init/last-artifacts-<UID>` | (v4.7.6+) artifact mirror。运行中 append；正常退出会清除；异常崩溃时遗留，下次启动会展示"遗留改动"清单提示操作员手动清理 |

### 🔁 幂等性 / 重复执行

* 脚本采用**托管块**机制：再次执行时**先删除旧块再写入新块**，不会重复堆积
* sudoers 文件名固定为 `server-init-<user>`，再次执行会覆盖而非新建
* **从 < v4.7.0 升级**：旧版本会留下时间戳形式的 sudoers 文件 (`server-init-<user>-YYYYMMDD...`)。v4.7.1 起在下次运行时**自动清理**这些遗留文件；v4.7.2 起**严格匹配纯数字后缀**，确保管理员自建的 `server-init-<user>-<非数字>` 文件（如 `server-init-admin-special-policy`）不会被误删，且不会跨用户误删兄弟账号的稳定文件。每次清理会在 audit log 记录 `LEGACY_SUDOERS_REMOVED`
* 备份目录每次按时间戳新建；最多保留 **10** 个最近备份，更旧的自动清理

### 🚪 退出码

| 退出码 | 含义 |
| :---: | :--- |
| 0 | 成功 |
| 1 | 通用错误 / 用户取消 / 配置失败 |
| 130 | `SIGINT` (Ctrl-C) |
| 143 | `SIGTERM` |
| 129 | `SIGHUP` |
| ≠0 (执行中途) | 触发自动回滚；查看 `/var/log/server-init.log` 与 `audit.log` |

> 注意：Ctrl-C 在 **确认提示** 阶段触发时，此时尚未发生破坏性变更，**不会**进入回滚路径。

### 📂 日志与审计

脚本执行后会生成以下重要文件，用于排查问题或审计合规：

> 📋 **日志轮转建议**：以下三个日志文件由脚本以**追加**方式写入，没有自带轮转机制。在频繁运行（CI/批量装机）的场景下建议加 `logrotate` 配置：
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

* **运行日志**: `/var/log/server-init.log` (包含详细的 debug 信息)
* **审计日志**: `/var/log/server-init-audit.log` (记录关键操作 Action、时间戳及操作人)
  * 主要 Action 类别（**应监控加粗项**）：
    * **生命周期**: `START` / `DONE` / **`ROLLBACK`** / **`RESTART_REFUSED`**
    * **账号**: `USER_CREATED` / `PASSWORD_CLEARED` / `KEYS_DEPLOYED` / **`ACCOUNT_KEPT_LOCKED`** / **`USER_REMOVE_FAILED`**
    * **sudo**: `SUDOERS_WRITTEN` / **`SUDO_FAIL`** / `LEGACY_SUDOERS_REMOVED`
    * **系统配置**: `MANAGED_BLOCK_INSTALLED` / `DROPIN_RENAMED` / `SYSTEMD_OVERRIDE_WRITTEN` / `MOTD_BANNER_WRITTEN` / `BBR_ENABLED` / `SYSTEM_UPDATE_START` / `SYSTEM_UPDATE_DONE`
    * **防火墙**: `FIREWALL_OPENED` / `FIREWALL_NOOP` / `STALE_FIREWALL_REMOVED` / `LAST_APPLIED_CLEARED`
    * **SELinux**: `SELINUX_PORT_ADDED` / `SELINUX_PORT_NOOP` / `SELINUX_PORT_MODIFIED` / **`SELINUX_PORT_FAIL`** / `STALE_SELINUX_REMOVED` / **`STALE_SELINUX_REMOVE_FAILED`** / `STALE_SELINUX_KEPT` / `STALE_SELINUX_SKIP`
    * **回滚不完整告警**（重点告警）: **`ROLLBACK_RM_FAILED`** / **`ROLLBACK_MOTD_FAILED`** / **`ROLLBACK_MOTD_BAK_MISSING`** / **`STRANDED_MUTATIONS_DETECTED`**
    * **测试 / 安全相关**: `LOGIN_TEST_PASSED` / `LOGIN_TEST_INCONCLUSIVE` / `INSECURE_KEY_URL` / `KEY_FETCH_FAILED` / `DIRECT_SPAWN` / `DIRECT_SPAWN_REFUSED`
  * stderr 后备格式（当 `/var/log` 不可写时）：`AUDIT-FALLBACK <timestamp> ACTION=<name> DETAILS=<...>`
  * 适合接入 SIEM 进行集中审计
* **健康报告**: `/var/log/server-init-health.log` (最终的系统配置状态快照)

### 🆘 灾难恢复与配置还原

脚本拥有两层安全机制：**运行时自动回滚** 和 **持久化备份恢复**。

如果在脚本执行完成后（显示 "DONE" 后）您无法连接服务器，请通过云服务商的 VNC / Console 控制台登录，并使用以下方法恢复。

#### 方法 A：使用一键恢复脚本 (推荐)

脚本在修改前会自动创建带 **SHA256 校验** 的备份。`restore.sh` 在覆盖前会校验 `checksums.sha256`，被篡改的备份将被拒绝。

1.  找到最近的备份目录：
    ```bash
    ls -ld /var/backups/ssh-config/*
    ```
2.  进入目录并运行恢复脚本：
    ```bash
    cd /var/backups/ssh-config/<TIMESTAMP>/
    sh restore.sh
    ```
    `restore.sh` 会：① 校验校验和 → ② 覆盖 `sshd_config` 及 `sshd_config.d/` → ③ 运行 `sshd -t` → ④ 重启 sshd。任一步骤失败都会以非 0 退出码停止。

    **覆盖校验**：若 `checksums.sha256` 缺失或系统无 `sha256sum`，`restore.sh` 会**拒绝执行**（防止恢复被篡改的备份）。如果你确信备份完整且必须强制恢复（例如手动删除了 checksums 文件），可以：
    ```bash
    FORCE=1 sh restore.sh
    ```
    仅在你**信任备份内容**时使用。

> 注意：`restore.sh` 仅还原 **`sshd_config` 与 drop-in**；运行期创建的用户、sudoers、systemd override、防火墙规则等需依靠**运行时自动回滚**或手动撤销（见上方的"脚本修改/创建的文件"清单）。

#### 方法 B：手动恢复

如果 `restore.sh` 不可用，可手动复制文件：

```bash
# 1. 校验 (可选但强烈推荐)
cd /var/backups/ssh-config/<TIMESTAMP>/ && sha256sum -c checksums.sha256

# 2. 覆盖配置文件
cp /var/backups/ssh-config/<TIMESTAMP>/sshd_config /etc/ssh/sshd_config

# 3. 重启服务
systemctl restart sshd || service sshd restart
```

---

### ⚠️ 免责声明

本脚本会修改核心系统配置（SSH）。虽然脚本内置了多重安全检查和回滚机制，但请务必确保你拥有服务器的备用访问方式（如 VNC 控制台），以防网络波动或配置意外导致的连接中断。

### 📄 开源协议

本项目采用 [MIT License](LICENSE) 开源。

---

<div align="center">

如果您觉得这个工具好用，请给一颗 ⭐ 星！

[报告问题](https://github.com/247like/linux-ssh-init-sh/issues) · [功能建议](https://github.com/247like/linux-ssh-init-sh/issues)

</div>
