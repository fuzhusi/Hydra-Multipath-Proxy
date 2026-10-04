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
#       openssl、systemd。本项目目前【没有远程发布产物】（无 GitHub
#       release、无预编译包），因此本脚本只做本地构建+本地安装，
#       不做任何远程下载——如实说明，避免误导。
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

# ── 4. 生成环境配置（密钥管理最佳实践: root:600，不进 history）──
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
HYDRA_MODE=masquerade
# 启用 obfs 逃生舱时取消注释并填入独立混淆密码（两端一致，勿与认证密钥相同）:
#HYDRA_OBFS_KEY=
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
if [[ $ENABLE -eq 1 ]]; then
  systemctl enable --now hydra-node.service
  systemctl --no-pager --lines=5 status hydra-node.service || true
else
  systemctl enable hydra-node.service
  echo "（--no-enable: 已 enable 但未启动。人工检查 $ENV_FILE 后执行: systemctl start hydra-node）"
fi

# ── 收尾提示 ─────────────────────────────────────────────────────
echo
echo "════════════════════════════════════════════════════════════"
if [[ $GENERATED_KEY -eq 1 ]]; then
  echo "节点自动生成了认证密钥（客户端 HYDRA_AUTH_KEY 必须与此一致）:"
  echo "  $AUTH_KEY"
  echo "  （注意: 上面这行已留在终端回滚缓冲，介意可 systemctl restart 后用"
  echo "    sudo grep ^HYDRA_AUTH_KEY $ENV_FILE 查看）"
else
  echo "认证密钥: 见 $ENV_FILE（sudo grep ^HYDRA_AUTH_KEY $ENV_FILE）"
fi
echo
echo "下一步:"
echo "  1. 防火墙放行节点端口（UDP）:   sudo ufw allow 443/udp"
echo "     （健康检查只绑 127.0.0.1，无需也【不要】对外放行）"
echo "  2. 首次启动后把证书复制给客户端（pinning 用）:"
echo "     sudo scp $NODE_DIR/hydra-node-cert.der <客户端机器>:<路径>"
echo "  3. 客户端设置 HYDRA_AUTH_KEY（同上密钥）与 HYDRA_NODE_CERT（证书路径）"
echo "  4. 排障手册: docs/guides/部署指南.md"
echo "════════════════════════════════════════════════════════════"
