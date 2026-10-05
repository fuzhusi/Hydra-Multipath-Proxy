#!/usr/bin/env bash
#
# Hydra 节点一键安装（Linux + systemd）
#
# 用法（在项目根目录执行）:
#   sudo ./deploy/install.sh                 # 本地构建 + 安装 + enable --now
#   sudo ./deploy/install.sh --skip-build    # 跳过构建（二进制已构建好，如跨机拷贝的仓库）
#   sudo ./deploy/install.sh --no-enable     # 安装但不 enable/start，人工检查后再启
#
# 前置: 目标机已装 Rust 工具链（cargo，1.81+，见 Cargo.lock MSRV）、
#       openssl、systemd。发布产物见 GitHub Releases（tag v* 自动构建，
#       Linux tar.gz 含 hydra-node）；本脚本走本地构建+本地安装路线，
#       不做远程下载——两条路线二选一，避免版本混淆。
#
# 脚本做什么:
#   1. cargo build --release -p hydra-node
#   2. 二进制安装到 /usr/local/bin/hydra-node
#   3. 创建系统用户 hydra + 配置目录 /etc/hydra（750, hydra 属主）
#   4. 生成 /etc/hydra/env（600）: 密钥未提供则自动 openssl 生成
#   5. 安装 systemd unit + daemon-reload + enable
#
# 不做什么（如实声明）:
#   - 不自动改防火墙（只提示命令，见末尾输出）
#   - 不做密钥轮换/证书分发（手工 scp，见 docs/guides/部署指南.md）

set -euo pipefail

SKIP_BUILD=0
ENABLE=1
for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=1 ;;
    --no-enable)  ENABLE=0 ;;
    -h|--help)
      sed -n '3,24p' "$0"; exit 0 ;;
    *)
      echo "未知参数: $arg"; sed -n '5,9p' "$0"; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "错误: 请用 root 运行（sudo ./deploy/install.sh）" >&2
  exit 1
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_SRC="$REPO_DIR/target/release/hydra-node"
BIN_DST="/usr/local/bin/hydra-node"
NODE_DIR="/etc/hydra"
ENV_FILE="$NODE_DIR/env"
NODE_USER="hydra"
SERVICE_SRC="$REPO_DIR/deploy/hydra-node.service"
SERVICE_DST="/etc/systemd/system/hydra-node.service"

# ── 1. 本地构建 ──────────────────────────────────────────────────
if [[ $SKIP_BUILD -eq 0 ]]; then
  echo "==> [1/5] cargo build --release -p hydra-node（首次构建需数分钟）"
  (cd "$REPO_DIR" && cargo build --release -p hydra-node)
else
  echo "==> [1/5] 跳过构建（--skip-build）"
fi
if [[ ! -x "$BIN_SRC" ]]; then
  echo "错误: 未找到可执行文件 $BIN_SRC，请先构建（去掉 --skip-build）" >&2
  exit 1
fi

# ── 2. 安装二进制 ────────────────────────────────────────────────
echo "==> [2/5] 安装二进制到 $BIN_DST"
install -m 0755 "$BIN_SRC" "$BIN_DST"

# ── 3. 专用用户与配置目录 ────────────────────────────────────────
echo "==> [3/5] 创建系统用户 $NODE_USER 与配置目录 $NODE_DIR"
if ! id -u "$NODE_USER" &>/dev/null; then
  useradd --system --user-group --home-dir "$NODE_DIR" \
          --shell /usr/sbin/nologin "$NODE_USER"
fi
install -d -o "$NODE_USER" -g "$NODE_USER" -m 0750 "$NODE_DIR"

# ── 4. 生成环境配置（审查 R-46，注释如实化：属主 hydra:hydra 0600——
#      服务以 hydra 用户运行需可读；ProtectSystem=strict 下 hydra 用户
#      亦无法篡改 unit/二进制。不进 shell history：本文件非交互写入）──
GENERATED_KEY=0
if [[ -f "$ENV_FILE" ]]; then
  echo "==> [4/5] $ENV_FILE 已存在，保留（升级不覆盖密钥与证书）"
else
  echo "==> [4/5] 生成 $ENV_FILE"
  AUTH_KEY="${HYDRA_AUTH_KEY:-}"
  if [[ -z "$AUTH_KEY" ]]; then
    if ! command -v openssl &>/dev/null; then
      echo "错误: 未安装 openssl 且未通过环境变量提供 HYDRA_AUTH_KEY。" >&2
      echo "      请安装 openssl 重跑，或手动复制 deploy/env.example 为 $ENV_FILE 并填入密钥。" >&2
      exit 1
    fi
    AUTH_KEY="$(openssl rand -hex 32)"
    GENERATED_KEY=1
  fi
  cat > "$ENV_FILE" <<EOF
# Hydra 节点环境变量（由 deploy/install.sh 生成）
# 修改后执行: systemctl restart hydra-node
# 警告: 密钥勿用 export 设置（会进 shell history），请用 vi 编辑本文件
HYDRA_AUTH_KEY=$AUTH_KEY
HYDRA_LISTEN=0.0.0.0:443
# 传输 = TCP/TLS（TLS 1.3 + Noise-PSK），唯一传输，无需配置
# 健康检查端点（可选，只绑回环，供拨测探活）:
HYDRA_HEALTH_ADDR=127.0.0.1:8081
EOF
  chown "$NODE_USER:$NODE_USER" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
fi

# ── 5. systemd: 安装 unit + reload + enable ──────────────────────
echo "==> [5/5] 安装 systemd unit 并启用"
install -m 0644 "$SERVICE_SRC" "$SERVICE_DST"
systemctl daemon-reload

# 升级场景识别：unit 此前已存在且服务当前 active → 安装后自动重启，
# 让新版二进制生效（否则旧进程继续跑旧代码，升级等于没生效）。
# 全新安装路径（unit 原不存在）行为不变：走 enable --now / enable。
IS_UPGRADE=0
if systemctl is-active --quiet hydra-node.service 2>/dev/null; then
  IS_UPGRADE=1
fi

if [[ $ENABLE -eq 1 ]]; then
  if [[ $IS_UPGRADE -eq 1 ]]; then
    echo "==> 检测到已有 hydra-node 服务在运行（升级场景），重启以加载新二进制"
    systemctl restart hydra-node.service
    systemctl --no-pager --lines=5 status hydra-node.service || true
    echo "    ✓ hydra-node 已重启"
  else
    systemctl enable --now hydra-node.service
    systemctl --no-pager --lines=5 status hydra-node.service || true
  fi
else
  systemctl enable hydra-node.service
  if [[ $IS_UPGRADE -eq 1 ]]; then
    echo "（--no-enable: 升级场景。服务此前已在运行，人工确认后执行: systemctl restart hydra-node）"
  else
    echo "（--no-enable: 已 enable 但未启动。人工检查 $ENV_FILE 后执行: systemctl start hydra-node）"
  fi
fi

# ── 6. 内核网络加固: BBR + fq（协议优化评估 P0 项，跨境高丢包链路收益显著）──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/99-hydra-bbr.conf" ]] && sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q .; then
  echo "==> [附加] 尝试启用内核 BBR + fq"
  install -m 0644 "$SCRIPT_DIR/99-hydra-bbr.conf" /etc/sysctl.d/99-hydra-bbr.conf
  sysctl --system >/dev/null 2>&1 || true
  if sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
    echo "    ✓ BBR + fq 已启用"
  else
    echo "    ⚠ BBR 未生效（内核或 VPS 虚拟化不支持，如 OpenVZ）。保持默认 CUBIC，可忽略。"
  fi
fi

# ── 收尾提示 ─────────────────────────────────────────────────────
echo
echo "════════════════════════════════════════════════════════════"
if [[ $GENERATED_KEY -eq 1 ]]; then
  # 审查 R-46（Wave 3 修复）：不再把明文密钥 echo 到终端（会留在回滚缓冲/
  # 会话日志里）；统一指向 env 文件查看。
  echo "节点自动生成了认证密钥（客户端 HYDRA_AUTH_KEY 必须与此一致）:"
  echo "  查看: sudo grep ^HYDRA_AUTH_KEY $ENV_FILE"
  echo "  （密钥不回显终端，避免留在终端回滚缓冲与会话日志中）"
else
  echo "认证密钥: 见 $ENV_FILE（sudo grep ^HYDRA_AUTH_KEY $ENV_FILE）"
fi
echo
echo "下一步:"
echo "  1. 防火墙放行节点端口（TCP）:   sudo ufw allow 443/tcp"
echo "     （健康检查只绑 127.0.0.1，无需也【不要】对外放行）"
echo "  2. 首次启动后把证书复制给客户端（pinning 用）:"
echo "     sudo scp $NODE_DIR/hydra-node-cert.der <客户端机器>:<路径>"
echo "  3. 客户端设置 HYDRA_AUTH_KEY（同上密钥）与 HYDRA_NODE_CERT（证书路径）"
echo "     （真证书部署：HYDRA_CERT_FILE/HYDRA_KEY_FILE 指向 PEM 后，客户端改设"
echo "      HYDRA_TRUST=ca，无需分发证书）"
echo "  4. 排障手册: docs/guides/部署指南.md"
echo "════════════════════════════════════════════════════════════"
