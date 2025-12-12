# Linux 服务器初始化与 SSH 安全加固

<p align="center">
  <strong>
    🇨🇳 中文文档 | <a href="README_en.md">🇺🇸 English</a>
  </strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Shell-POSIX_sh-blue?style=flat-square" alt="POSIX Shell">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/github/v/release/247like/linux-ssh-init-sh?style=flat-square" alt="Release">
  <img src="https://img.shields.io/github/stars/247like/linux-ssh-init-sh?style=flat-square" alt="Stars">
</p>

---

一个生产就绪、符合 POSIX 标准的 Shell 脚本，用于 Linux 服务器的一键初始化与 SSH 安全加固。

该脚本可自动完成 **SSH 密钥配置**、**修改端口**、**创建用户**、**开启 BBR** 以及 **系统更新**，并完美兼容 Debian, Ubuntu, CentOS, RHEL 以及 Alpine Linux。

### ✨ 核心特性

* **全平台兼容**: 完美支持 **Debian 10/11/12**, **Ubuntu**, **CentOS 7/8/9**, **Alma/Rocky**, 以及 **Alpine Linux**。
* **POSIX 标准**: 纯 `/bin/sh` 编写，无需安装 `bash`。在 `dash` (Debian) 和 `ash` (Alpine/Busybox) 上稳定运行。
* **安全设计架构**:
    * **头部管理块**: 将配置插入 `sshd_config` 最顶部，完美覆盖 Debian 12 默认的 `Include` 配置陷阱。
    * **原子化验证**: 修改后自动执行 `sshd -t` 校验，若校验失败则**自动回滚**配置。
    * **防失联机制**: 如果 SSH 公钥下载或部署失败，脚本**不会**强制关闭密码登录。
    * **防火墙感知**: 修改端口时，自动识别并放行 `ufw` 或 `firewalld`。
* **自动化友好**:
    * 支持 **无头模式 (Headless)**，通过命令行参数实现零交互无人值守安装。
    * **随机高位端口**: 自动生成 20000-60000 之间的随机端口并检测占用。

### 🚀 快速开始

请以 **root** 身份运行。

#### 1. 交互式运行 (推荐)
```bash
curl -fsSL https://raw.githubusercontent.com/247like/linux-ssh-init-sh/main/init.sh -o init.sh && chmod +x init.sh && ./init.sh
```

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
| **用户与端口** | `--user=root` | 指定登录用户 (root 或普通用户名) |
| | `--port=22` | 保持默认 22 端口 |
| | `--port=random` | 生成随机高位端口 (20000-60000) |
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
| **公钥失败** | 若下载失败，脚本**保留密码登录**并警告。<br>👉 *结果：服务器不安全，但能登录修补。* | 脚本**立即报错退出**，不修改任何配置。<br>👉 *结果：部署中断，保持原样。* |
| **端口失败** | 若随机端口失败，回退使用 **端口 22**。 | 脚本**立即报错退出**。 |
| **适用场景** | 手动操作、网络环境不稳定。 | 自动化运维、CI/CD、高安全要求环境。 |

### 🛠️ 执行流程细节

1.  **环境检测**: 自动识别包管理器 (`apt`/`yum`/`apk`) 并安装 `curl`, `sudo`, `openssh-server` 等依赖。
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
