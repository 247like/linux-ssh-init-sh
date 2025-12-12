# Linux 服务器初始化与 SSH 安全加固

<p align="center">
  <img src="https://img.shields.io/badge/Shell-POSIX_sh-blue?style=flat-square" alt="POSIX Shell">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/github/v/release/247like/linux-ssh-init-sh?style=flat-square" alt="Release">
  <img src="https://img.shields.io/github/stars/247like/linux-ssh-init-sh?style=flat-square" alt="Stars">
</p>

<p align="center">
  <strong>
    🇨🇳 中文文档 | <a href="README_EN.md">🇺🇸 English</a>
  </strong>
</p>

---

一个生产就绪、符合 POSIX 标准的 Shell 脚本，用于 Linux 服务器的一键初始化与 SSH 安全加固。

该脚本可自动完成 **SSH 密钥配置**、**修改端口**、**创建用户**、**开启 BBR** 以及 **系统更新**，并完美兼容 Debian, Ubuntu, CentOS, RHEL 以及 Alpine Linux。

### ✨ 核心特性

* **全平台兼容**: 完美支持 **Debian 10/11/12**, **Ubuntu**, **CentOS 7/8/9**, **Alma/Rocky**, 以及 **Alpine Linux**。
* **POSIX 标准**: 纯 `/bin/sh` 编写，无需安装 `bash`。在 `dash` (Debian) 和 `ash` (Alpine/Busybox) 上稳定运行。
* **安全设计架构**:
    * **头部管理块 (Managed Block)**: 将安全配置插入 `sshd_config` 的**最顶部**，从而覆盖 Debian 12 默认的 `Include` 配置陷阱。
    * **原子化验证**: 修改后自动执行 `sshd -t` 校验，若校验失败则**自动回滚**配置，防止服务挂掉。
    * **防失联机制**: 如果 SSH 公钥下载或部署失败，脚本**不会**强制关闭密码登录，确保你不会把自己锁在门外。
    * **防火墙感知**: 修改端口时，自动识别并放行 `ufw` 或 `firewalld`。
* **智能交互**:
    * 支持从 **GitHub**、**URL** 自动拉取公钥，或支持多行**手动粘贴**。
    * **随机高位端口**: 自动生成 20000-60000 之间的随机端口，并使用 `ss`/`netstat` 检测占用情况。
    * **系统优化**: 可选开启 **TCP BBR** 拥塞控制及系统软件更新。

### 🚀 快速开始

请以 **root** 身份运行。

#### 标准运行 (交互式)，默认中文
```bash
curl -fsSL [https://raw.githubusercontent.com/247like/linux-ssh-init-sh/main/init.sh](https://raw.githubusercontent.com/247like/linux-ssh-init-sh/main/init.sh) -o init.sh && chmod +x init.sh && ./init.sh
```

#### 使用英文
```bash
curl -fsSL [https://raw.githubusercontent.com/247like/linux-ssh-init-sh/main/init.sh](https://raw.githubusercontent.com/247like/linux-ssh-init-sh/main/init.sh) -o init.sh && chmod +x init.sh && ./init.sh --lang=zh
```

### ⚙️ 参数说明

脚本支持以下运行时参数：

| 参数 | 说明 |
| :--- | :--- |
| `--lang=zh` | 强制使用**中文**交互界面。 |
| `--lang=en` | 强制使用**英文**交互界面。 |
| `--strict` | **严格模式**。若开启，遇到任何非致命错误（如公钥下载失败、随机端口生成失败）时，脚本将**立即退出**，而不是降级处理（如回退到端口 22 或保留密码登录）。适合对安全要求极高的场景。 |

### ⚙️ 普通模式 vs 严格模式

| 场景 | 普通模式 (默认) | 严格模式 (`--strict`) |
| :--- | :--- | :--- |
| **设计理念** | **"优先保命"** (尽力而为) | **"优先合规"** (零容忍) |
| **公钥失败** | 如果公钥下载失败，脚本**保留密码登录**并警告。<br>👉 *结果：服务器不安全，但能登录修补。* | 脚本**立即报错退出**，不修改任何配置。<br>👉 *结果：部署中断，保持原样。* |
| **端口失败** | 如果随机端口生成失败，回退使用 **端口 22**。 | 脚本**立即报错退出**。 |
| **适用场景** | 手动操作、网络环境不稳定。 | 自动化运维、CI/CD、高安全要求环境。 |

### 💡 使用示例

**1. 交互式初始化 (中文):**
```bash
./init.sh --lang=zh
```

**2. 严格模式 (自动化/高安全场景):**
*如果公钥下载失败，脚本将直接报错退出，而不会允许使用密码登录。*
```bash
./init.sh --strict
```

### 🛠️ 执行流程细节

1.  **环境检测**: 自动识别包管理器 (`apt`/`yum`/`apk`) 并安装 `curl`, `sudo`, `openssh-server` 等必要依赖。
2.  **用户管理**: 创建指定用户（若非 root）并配置免密 Sudo 权限。
3.  **密钥部署**: 部署 SSH 公钥，自动修正 `.ssh` 目录权限，支持去重。
4.  **SSH 加固**:
    * 备份 `sshd_config`。
    * 清理旧的脚本配置块。
    * 在文件**头部**写入新的安全配置（禁密码、改端口等），确保优先级最高。
5.  **收尾工作**: 验证配置语法，重启 SSH 服务，并根据选择应用 BBR 或系统更新。

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
