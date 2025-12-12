#!/bin/sh
# =========================================================
# linux-ssh-init-sh
# Server Init & SSH Hardening Script
#
# Release: v1.0.0 (Initial Production Release)
#
# POSIX sh compatible (dash / ash / busybox)
#
# Logic Baseline:
#   v2.2 – Production-hardened internal version
#   (Debian 12 Include-safe, SSH lockout-safe)
#
# Changes in v1.0.0:
#   - Public open-source release
#   - Integrated i18n (English / 中文)
#   - User-visible messages only
#   - NO changes to execution flow or security logic
#
# Repository:
#   https://github.com/247like/linux-ssh-init-sh
#
# =========================================================

set -eu

# ---------------- Language Config ----------------
LANG_CUR="zh" # Default

# ---------------- Automation Variables ----------------
ARG_USER=""
ARG_PORT=""     # "22", "random", or specific number
ARG_KEY_TYPE="" # "gh", "url", "raw"
ARG_KEY_VAL=""
ARG_UPDATE=""   # "y" or "n"
ARG_BBR=""      # "y" or "n"
AUTO_CONFIRM="n"
STRICT_MODE="n"

# Parse Arguments
for a in "$@"; do
  case "$a" in
    --lang=zh)     LANG_CUR="zh" ;;
    --lang=en)     LANG_CUR="en" ;;
    --strict)      STRICT_MODE="y" ;;
    --yes)         AUTO_CONFIRM="y" ;;
    
    --user=*)      ARG_USER="${a#*=}" ;;
    
    --port=random) ARG_PORT="random" ;;
    --port=*)      ARG_PORT="${a#*=}" ;;
    
    --key-gh=*)    ARG_KEY_TYPE="gh";  ARG_KEY_VAL="${a#*=}" ;;
    --key-url=*)   ARG_KEY_TYPE="url"; ARG_KEY_VAL="${a#*=}" ;;
    --key-raw=*)   ARG_KEY_TYPE="raw"; ARG_KEY_VAL="${a#*=}" ;;
    
    --update)      ARG_UPDATE="y" ;;
    --no-update)   ARG_UPDATE="n" ;;
    
    --bbr)         ARG_BBR="y" ;;
    --no-bbr)      ARG_BBR="n" ;;
  esac
done

# Simple language selector if not provided via arg
if [ -z "${LANG_CUR}" ]; then
  true # Default is EN, logic kept simple for automation
fi

# ---------------- Messages ----------------
msg() {
  key="$1"
  if [ "$LANG_CUR" = "zh" ]; then
    case "$key" in
      MUST_ROOT)   echo "必须以 root 权限运行此脚本" ;;
      BANNER)      echo "服务器初始化 & SSH 安全加固 (v2.4 Auto)" ;;
      STRICT_ON)   echo "STRICT 模式已开启：任何关键错误将直接退出" ;;
      ASK_USER)    echo "SSH 登录用户 (root 或普通用户，默认 " ;;
      ASK_PORT_T)  echo "SSH 端口配置：" ;;
      OPT_PORT_1)  echo "1) 使用 22 (默认)" ;;
      OPT_PORT_2)  echo "2) 随机高端口 (推荐)" ;;
      OPT_PORT_3)  echo "3) 手动指定" ;;
      SELECT)      echo "请选择 [1-3]: " ;;
      INPUT_PORT)  echo "请输入端口号 (1024-65535): " ;;
      PORT_ERR)    echo "❌ 端口输入无效 (非数字或超范围)" ;;
      ASK_KEY_T)   echo "SSH 公钥来源：" ;;
      OPT_KEY_1)   echo "1) GitHub 用户导入" ;;
      OPT_KEY_2)   echo "2) URL 下载" ;;
      OPT_KEY_3)   echo "3) 手动粘贴" ;;
      INPUT_GH)    echo "请输入 GitHub 用户名: " ;;
      INPUT_URL)   echo "请输入公钥 URL: " ;;
      INPUT_RAW)   echo "请粘贴公钥内容 (空行结束输入): " ;;
      ASK_UPD)     echo "是否更新系统软件包? [y/n] (默认 n): " ;;
      ASK_BBR)     echo "是否开启 BBR 加速? [y/n] (默认 n): " ;;
      CONFIRM_T)   echo "---------------- 执行确认 ----------------" ;;
      C_USER)      echo "登录用户: " ;;
      C_PORT)      echo "端口模式: " ;;
      C_KEY)       echo "密钥来源: " ;;
      C_UPD)       echo "系统更新: " ;;
      C_BBR)       echo "开启 BBR: " ;;
      WARN_FW)     echo "⚠ 注意：修改端口前，请确认云厂商防火墙/安全组已放行对应 TCP 端口" ;;
      ASK_SURE)    echo "确认执行? [y/n]: " ;;
      CANCEL)      echo "已取消操作" ;;
      I_INSTALL)   echo "正在安装基础依赖..." ;;
      I_UPD)       echo "正在更新系统..." ;;
      I_BBR)       echo "正在配置 BBR..." ;;
      I_USER)      echo "正在配置用户..." ;;
      I_SSH_INSTALL) echo "未检测到 OpenSSH，正在安装..." ;;
      I_KEY_OK)    echo "公钥部署成功" ;;
      W_KEY_FAIL)  echo "公钥部署失败，将保留密码登录以防失联" ;;
      I_BACKUP)    echo "已备份配置: " ;;
      E_SSHD_CHK)  echo "sshd 配置校验失败，已回滚" ;;
      W_RESTART)   echo "无法自动重启 SSH 服务，请手动重启" ;;
      DONE_T)      echo "================ 完成 ================" ;;
      DONE_MSG1)   echo "请【不要关闭】当前窗口。" ;;
      DONE_MSG2)   echo "请新开一个终端窗口测试登录：" ;;
      DONE_FW)     echo "⚠ 若无法连接，请再次检查防火墙设置" ;;
      AUTO_SKIP)   echo "检测到参数输入，跳过询问: " ;;
      *)           echo "$key" ;;
    esac
  else
    case "$key" in
      MUST_ROOT)   echo "Must be run as root" ;;
      BANNER)      echo "Server Init & SSH Hardening (v2.4 Auto)" ;;
      STRICT_ON)   echo "STRICT mode ON: Critical errors will abort" ;;
      ASK_USER)    echo "SSH Login User (root or normal user, default " ;;
      ASK_PORT_T)  echo "SSH Port Configuration:" ;;
      OPT_PORT_1)  echo "1) Use 22 (Default)" ;;
      OPT_PORT_2)  echo "2) Random High Port (Recommended)" ;;
      OPT_PORT_3)  echo "3) Manual Input" ;;
      SELECT)      echo "Select [1-3]: " ;;
      INPUT_PORT)  echo "Enter Port (1024-65535): " ;;
      PORT_ERR)    echo "❌ Invalid port (not numeric or out of range)" ;;
      ASK_KEY_T)   echo "SSH Public Key Source:" ;;
      OPT_KEY_1)   echo "1) GitHub User" ;;
      OPT_KEY_2)   echo "2) URL Download" ;;
      OPT_KEY_3)   echo "3) Manual Paste" ;;
      INPUT_GH)    echo "Enter GitHub Username: " ;;
      INPUT_URL)   echo "Enter Key URL: " ;;
      INPUT_RAW)   echo "Paste Key (Empty line to finish): " ;;
      ASK_UPD)     echo "Update system packages? [y/n] (default n): " ;;
      ASK_BBR)     echo "Enable TCP BBR? [y/n] (default n): " ;;
      CONFIRM_T)   echo "---------------- Confirmation ----------------" ;;
      C_USER)      echo "User: " ;;
      C_PORT)      echo "Port: " ;;
      C_KEY)       echo "Key Source: " ;;
      C_UPD)       echo "Update: " ;;
      C_BBR)       echo "Enable BBR: " ;;
      WARN_FW)     echo "⚠ WARNING: Ensure Cloud Firewall/Security Group allows the new TCP port" ;;
      ASK_SURE)    echo "Proceed? [y/n]: " ;;
      CANCEL)      echo "Cancelled." ;;
      I_INSTALL)   echo "Installing dependencies..." ;;
      I_UPD)       echo "Updating system..." ;;
      I_BBR)       echo "Configuring BBR..." ;;
      I_USER)      echo "Configuring user..." ;;
      I_SSH_INSTALL) echo "OpenSSH not found, installing..." ;;
      I_KEY_OK)    echo "SSH Key deployed successfully" ;;
      W_KEY_FAIL)  echo "Key deployment failed. Password login kept enabled to avoid lockout." ;;
      I_BACKUP)    echo "Backup created: " ;;
      E_SSHD_CHK)  echo "sshd config validation failed, rolled back." ;;
      W_RESTART)   echo "Could not restart sshd automatically. Please restart manually." ;;
      DONE_T)      echo "================ DONE ================" ;;
      DONE_MSG1)   echo "Please DO NOT close this window yet." ;;
      DONE_MSG2)   echo "Open a NEW terminal to test login:" ;;
      DONE_FW)     echo "⚠ If connection fails, check your Firewall settings." ;;
      AUTO_SKIP)   echo "Argument detected, skipping prompt: " ;;
      *)           echo "$key" ;;
    esac
  fi
}

# =========================================================
# Core Logic
# =========================================================

LOG_FILE="/var/log/server-init.log"
SSH_CONF="/etc/ssh/sshd_config"
DEFAULT_USER="deploy"

BLOCK_BEGIN="# BEGIN SERVER-INIT MANAGED BLOCK"
BLOCK_END="# END SERVER-INIT MANAGED BLOCK"

# Flags
APT_UPDATED="n"
APK_UPDATED="n"
YUM_PREPARED="n"

log() { echo "$(date '+%F %T') $*" >>"$LOG_FILE"; }
info() { echo "\033[0;34m[INFO]\033[0m $*"; log "[INFO] $*"; }
warn() { echo "\033[0;33m[WARN]\033[0m $*"; log "[WARN] $*"; }
err() { echo "\033[0;31m[ERR ]\033[0m $*"; log "[ERR ] $*"; }
die() { err "$*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "$(msg MUST_ROOT)"
touch "$LOG_FILE" 2>/dev/null || true

# ---------------- package manager ----------------
detect_pm() {
  [ -f /etc/alpine-release ] && { echo apk; return; }
  [ -f /etc/debian_version ] && { echo apt; return; }
  [ -f /etc/redhat-release ] && { echo yum; return; }
  echo unknown
}
PM="$(detect_pm)"

pm_prepare_once() {
  case "$PM" in
    apt)
      if [ "$APT_UPDATED" != "y" ]; then
        apt-get update -y >>"$LOG_FILE" 2>&1
        APT_UPDATED="y"
      fi
      ;;
    apk)
      if [ "$APK_UPDATED" != "y" ]; then
        apk update >>"$LOG_FILE" 2>&1 || true
        APK_UPDATED="y"
      fi
      ;;
    yum)
      if [ "$YUM_PREPARED" != "y" ]; then
        if command -v dnf >/dev/null 2>&1; then dnf makecache -y >>"$LOG_FILE" 2>&1 || true
        else yum makecache -y >>"$LOG_FILE" 2>&1 || true; fi
        YUM_PREPARED="y"
      fi
      ;;
  esac
}

install_pkg() {
  case "$PM" in
    apt)
      pm_prepare_once
      DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >>"$LOG_FILE" 2>&1
      ;;
    yum)
      pm_prepare_once
      if command -v dnf >/dev/null 2>&1; then dnf install -y "$@" >>"$LOG_FILE" 2>&1
      else yum install -y "$@" >>"$LOG_FILE" 2>&1; fi
      ;;
    apk)
      pm_prepare_once
      apk add --no-cache "$@" >>"$LOG_FILE" 2>&1
      ;;
    *)
      die "Unknown Package Manager"
      ;;
  esac
}

install_pkg_try() {
  for p in "$@"; do
    if install_pkg "$p" >/dev/null 2>&1; then return 0; fi
  done
  return 1
}

# ---------------- system update ----------------
update_system() {
  case "$PM" in
    apt)
      pm_prepare_once
      DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >>"$LOG_FILE" 2>&1
      ;;
    yum)
      pm_prepare_once
      if command -v dnf >/dev/null 2>&1; then dnf upgrade -y >>"$LOG_FILE" 2>&1
      else yum update -y >>"$LOG_FILE" 2>&1; fi
      ;;
    apk)
      pm_prepare_once
      apk upgrade >>"$LOG_FILE" 2>&1
      ;;
  esac
}

# ---------------- BBR ----------------
enable_bbr() {
  command -v sysctl >/dev/null 2>&1 || return
  
  if ! sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q bbr; then
    warn "Kernel does not support BBR, skipping."
    return
  fi

  sysctl_conf="/etc/sysctl.conf"
  grep -q '^net.core.default_qdisc=fq$' "$sysctl_conf" 2>/dev/null || \
    echo 'net.core.default_qdisc=fq' >>"$sysctl_conf"
  grep -q '^net.ipv4.tcp_congestion_control=bbr$' "$sysctl_conf" 2>/dev/null || \
    echo 'net.ipv4.tcp_congestion_control=bbr' >>"$sysctl_conf"

  sysctl -p >>"$LOG_FILE" 2>&1 || true
}

# ---------------- ssh server ensure ----------------
ensure_ssh_server() {
  [ -f "$SSH_CONF" ] && return 0
  info "$(msg I_SSH_INSTALL)"
  case "$PM" in
    apk) install_pkg openssh ;;
    *)   install_pkg openssh-server ;;
  esac
  [ -f "$SSH_CONF" ] || die "OpenSSH Install Failed"
}

# ---------------- restart sshd ----------------
restart_sshd() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart sshd >>"$LOG_FILE" 2>&1 || systemctl restart ssh >>"$LOG_FILE" 2>&1
    return 0
  fi
  if command -v rc-service >/dev/null 2>&1; then
    rc-service sshd restart >>"$LOG_FILE" 2>&1
    return 0
  fi
  if command -v service >/dev/null 2>&1; then
    service sshd restart >>"$LOG_FILE" 2>&1 || service ssh restart >>"$LOG_FILE" 2>&1
    return 0
  fi
  [ -x /etc/init.d/sshd ] && /etc/init.d/sshd restart >>"$LOG_FILE" 2>&1 && return 0
  [ -x /etc/init.d/ssh ]  && /etc/init.d/ssh  restart >>"$LOG_FILE" 2>&1 && return 0
  return 1
}

# ---------------- firewall ----------------
allow_firewall_port() {
  p="$1"
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "${p}/tcp" >>"$LOG_FILE" 2>&1 || true
  elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${p}/tcp" >>"$LOG_FILE" 2>&1 || true
    firewall-cmd --reload >>"$LOG_FILE" 2>&1 || true
  fi
}

# ---------------- random port ----------------
rand_u16() {
  if [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then
    od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' '
  else
    echo $(( ( $(date +%s 2>/dev/null || echo 12345) + $$ ) % 65536 ))
  fi
}

ensure_port_tools() {
  command -v ss >/dev/null 2>&1 && return 0
  command -v netstat >/dev/null 2>&1 && return 0
  case "$PM" in
    apt) install_pkg_try iproute2 >/dev/null 2>&1 || true ;;
    yum) install_pkg_try iproute  >/dev/null 2>&1 || true ;;
    apk) install_pkg_try iproute2 iproute2-ss >/dev/null 2>&1 || true ;;
  esac
  command -v ss >/dev/null 2>&1 && return 0
  install_pkg_try net-tools >/dev/null 2>&1 || true
}

is_port_free() {
  p="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -lnt 2>/dev/null | awk '{print $4}' | grep -q ":$p\$" && return 1 || return 0
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -lnt 2>/dev/null | awk '{print $4}' | grep -q ":$p\$" && return 1 || return 0
  fi
  return 1
}

pick_random_port() {
  ensure_port_tools
  i=0
  while [ $i -lt 80 ]; do
    r="$(rand_u16)"
    p=$(( (r % 40000) + 20000 ))
    if is_port_free "$p"; then echo "$p"; return 0; fi
    i=$((i+1))
  done
  return 1
}

# ---------------- user ensure ----------------
ensure_user() {
  u="$1"
  [ "$u" = "root" ] && return 0
  id "$u" >/dev/null 2>&1 && return 0

  info "$(msg I_USER) $u"
  install_pkg_try bash >/dev/null 2>&1 || true
  install_pkg_try sudo >/dev/null 2>&1 || true

  shell="/bin/sh"
  [ -x /bin/bash ] && shell="/bin/bash"

  if command -v useradd >/dev/null 2>&1; then
    useradd -m -s "$shell" "$u"
  else
    adduser -D -s "$shell" "$u"
  fi

  if [ -d /etc/sudoers.d ]; then
    echo "$u ALL=(ALL) NOPASSWD:ALL" >"/etc/sudoers.d/$u" 2>/dev/null || true
    chmod 440 "/etc/sudoers.d/$u" 2>/dev/null || true
  fi
}

# ---------------- managed block ----------------
remove_managed_block() {
  tmp="${SSH_CONF}.tmp.$$"
  awk -v b="$BLOCK_BEGIN" -v e="$BLOCK_END" '
    $0==b {skip=1; next}
    $0==e {skip=0; next}
    skip!=1 {print}
  ' "$SSH_CONF" >"$tmp"
  mv "$tmp" "$SSH_CONF"
}

insert_block_at_top() {
  block="$1"
  tmp="${SSH_CONF}.tmp.$$"
  cat "$block" "$SSH_CONF" >"$tmp"
  mv "$tmp" "$SSH_CONF"
}

build_block() {
  file="$1"
  {
    echo "$BLOCK_BEGIN"
    echo "# Managed by server-init. DO NOT edit inside this block."
    echo ""
    echo "Port $SSH_PORT"

    if [ "$KEY_OK" = "y" ]; then
      echo "PasswordAuthentication no"
      echo "ChallengeResponseAuthentication no"
      echo "PubkeyAuthentication yes"
    fi

    if [ "$TARGET_USER" = "root" ]; then
      if [ "$KEY_OK" = "y" ]; then
        echo "PermitRootLogin prohibit-password"
      else
        echo "PermitRootLogin yes"
      fi
    else
      echo "PermitRootLogin no"
    fi

    echo ""
    echo "$BLOCK_END"
    echo ""
  } >"$file"
}

# ---------------- key fetch ----------------
fetch_keys() {
  case "$1" in
    gh)  curl -fsSL "https://github.com/$2.keys" 2>>"$LOG_FILE" || true ;;
    url) curl -fsSL "$2" 2>>"$LOG_FILE" || true ;;
    raw) printf "%s\n" "$2" ;;
  esac
}

deploy_keys() {
  user="$1"
  keys="$2"

  home="$(eval echo "~$user")"
  dir="$home/.ssh"
  auth="$dir/authorized_keys"

  mkdir -p "$dir"
  chmod 700 "$dir"
  touch "$auth"
  chmod 600 "$auth"
  chown -R "$user:" "$dir" 2>/dev/null || true

  printf "%s\n" "$keys" | while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | grep -Eq '^(ssh-|ecdsa-)' || continue
    grep -qxF "$line" "$auth" || echo "$line" >>"$auth"
  done

  grep -Eq '^(ssh-|ecdsa-)' "$auth"
}

# =========================================================
# Phase 1: Input (Supports Automation)
# =========================================================
clear
echo "================================================="
msg BANNER
echo "================================================="
[ "$STRICT_MODE" = "y" ] && msg STRICT_ON

# 1. User
if [ -n "$ARG_USER" ]; then
  TARGET_USER="$ARG_USER"
  printf "%s%s\n" "$(msg AUTO_SKIP)" "$TARGET_USER"
else
  printf "%s%s): " "$(msg ASK_USER)" "$DEFAULT_USER"
  read TARGET_USER
  [ -z "$TARGET_USER" ] && TARGET_USER="$DEFAULT_USER"
fi

# 2. Port
if [ -n "$ARG_PORT" ]; then
  case "$ARG_PORT" in
    22)     PORT_OPT="1"; SSH_PORT="22" ;;
    random) PORT_OPT="2"; SSH_PORT="22" ;; # 22 is placeholder
    *)      PORT_OPT="3"; SSH_PORT="$ARG_PORT" ;;
  esac
  printf "%s%s\n" "$(msg AUTO_SKIP)" "$ARG_PORT (Mode $PORT_OPT)"
else
  echo ""
  msg ASK_PORT_T
  msg OPT_PORT_1
  msg OPT_PORT_2
  msg OPT_PORT_3
  printf "%s" "$(msg SELECT)"
  read PORT_OPT
  [ -z "$PORT_OPT" ] && PORT_OPT="1"

  SSH_PORT="22"
  if [ "$PORT_OPT" = "3" ]; then
    while :; do
      printf "%s" "$(msg INPUT_PORT)"
      read MANUAL_PORT
      echo "$MANUAL_PORT" | grep -Eq '^[0-9]+$' || { msg PORT_ERR; continue; }
      [ "$MANUAL_PORT" -ge 1024 ] 2>/dev/null && [ "$MANUAL_PORT" -le 65535 ] 2>/dev/null || { msg PORT_ERR; continue; }
      SSH_PORT="$MANUAL_PORT"
      break
    done
  fi
fi

# 3. Key
if [ -n "$ARG_KEY_TYPE" ]; then
  KEY_OPT="auto"
  KEY_TYPE="$ARG_KEY_TYPE"
  KEY_VAL="$ARG_KEY_VAL"
  printf "%s%s\n" "$(msg AUTO_SKIP)" "$KEY_TYPE ($KEY_VAL)"
else
  echo ""
  msg ASK_KEY_T
  msg OPT_KEY_1
  msg OPT_KEY_2
  msg OPT_KEY_3
  printf "%s" "$(msg SELECT)"
  read KEY_OPT

  case "$KEY_OPT" in
    1) KEY_TYPE="gh";  printf "%s" "$(msg INPUT_GH)"; read KEY_VAL ;;
    2) KEY_TYPE="url"; printf "%s" "$(msg INPUT_URL)"; read KEY_VAL ;;
    3)
       KEY_TYPE="raw"
       msg INPUT_RAW
       raw=""
       while IFS= read -r l; do
         [ -z "$l" ] && break
         raw="${raw}${l}\n"
       done
       KEY_VAL="$(printf "%b" "$raw")"
       ;;
    *) die "Invalid Option" ;;
  esac
fi

# 4. Update
if [ -n "$ARG_UPDATE" ]; then
  DO_UPDATE="$ARG_UPDATE"
  printf "%s%s\n" "$(msg AUTO_SKIP)" "Update=$DO_UPDATE"
else
  printf "%s" "$(msg ASK_UPD)"
  read DO_UPDATE
  [ -z "$DO_UPDATE" ] && DO_UPDATE="n"
fi

# 5. BBR
if [ -n "$ARG_BBR" ]; then
  DO_BBR="$ARG_BBR"
  printf "%s%s\n" "$(msg AUTO_SKIP)" "BBR=$DO_BBR"
else
  printf "%s" "$(msg ASK_BBR)"
  read DO_BBR
  [ -z "$DO_BBR" ] && DO_BBR="n"
fi

# =========================================================
# Phase 2: Confirm
# =========================================================
if [ "$AUTO_CONFIRM" = "y" ]; then
  echo ""
  echo "[Auto-Confirm] Skipping interactive confirmation."
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
  read CONFIRM
  [ "${CONFIRM:-n}" = "y" ] || die "$(msg CANCEL)"
fi

# =========================================================
# Phase 3: Execute
# =========================================================
info "$(msg I_INSTALL)"
ensure_ssh_server
install_pkg_try curl >/dev/null 2>&1 || die "curl install failed"

# Updates & BBR
if [ "$DO_UPDATE" = "y" ]; then
  info "$(msg I_UPD)"
  update_system
fi

if [ "$DO_BBR" = "y" ]; then
  info "$(msg I_BBR)"
  enable_bbr
fi

# Random Port (Handled here to use installed tools)
if [ "$PORT_OPT" = "2" ]; then
  p="$(pick_random_port || true)"
  if [ -n "$p" ]; then
    SSH_PORT="$p"
    info "Random Port: $SSH_PORT"
  else
    [ "$STRICT_MODE" = "y" ] && die "STRICT: Random port failed"
    warn "Random port failed, fallback to 22"
    SSH_PORT="22"
  fi
fi

# Firewall (Before restart)
[ "$SSH_PORT" != "22" ] && allow_firewall_port "$SSH_PORT"

# User ensure
ensure_user "$TARGET_USER"

# Key Deploy
KEY_OK="n"
KEY_DATA="$(fetch_keys "$KEY_TYPE" "$KEY_VAL")"
if [ -n "$KEY_DATA" ] && deploy_keys "$TARGET_USER" "$KEY_DATA"; then
  KEY_OK="y"
  info "$(msg I_KEY_OK)"
else
  [ "$STRICT_MODE" = "y" ] && die "STRICT: Key deploy failed"
  warn "$(msg W_KEY_FAIL)"
fi

# SSH Config Write
bak="${SSH_CONF}.bak_$(date +%F_%H%M%S)"
cp "$SSH_CONF" "$bak"
info "$(msg I_BACKUP)$bak"

remove_managed_block
tmp="/tmp/sshd_block.$$"
build_block "$tmp"
insert_block_at_top "$tmp"
rm -f "$tmp"

if ! sshd -t -f "$SSH_CONF" 2>>"$LOG_FILE"; then
  cp "$bak" "$SSH_CONF"
  die "$(msg E_SSHD_CHK)"
fi

if ! restart_sshd; then
  warn "$(msg W_RESTART)"
fi

# =========================================================
# Done
# =========================================================
echo ""
msg DONE_T
msg DONE_MSG1
msg DONE_MSG2
echo "   ssh -p $SSH_PORT $TARGET_USER@<IP>"
[ "$SSH_PORT" != "22" ] && msg DONE_FW
echo "Log: $LOG_FILE"
