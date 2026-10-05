# Hydra 节点镜像（多阶段构建）
#
# 构建:  docker build -t hydra-node:latest .
# 运行:  推荐 docker compose（见同目录 docker-compose.yml）
#
# 说明: 基础镜像用 rust:1-slim（滚动最新稳定版）。Cargo.lock 内多个
# 传递依赖（home 0.5.12、litemap 0.8.x 等）MSRV >= 1.81，更旧的
# 固定版本标签（如 1.75）无法编译本仓库，故不做降版承诺。

# ── 阶段 1: 构建 ──────────────────────────────────────────────────
FROM rust:1-slim AS builder
WORKDIR /build
# workspace 全量拷贝（根 Cargo.toml 声明了全部成员，无法只拷 manifests
# 做依赖缓存；代价是源码变更时全量重编，本项目体量可接受）
COPY . .
RUN cargo build --release -p hydra-node

# ── 阶段 2: 运行（debian-slim，仅二进制 + CA 证书）───────────────
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/hydra-node /usr/local/bin/hydra-node

# 专用非 root 用户；证书/私钥目录 /etc/hydra（节点默认把证书写到进程
# CWD，WORKDIR 固定到 /etc/hydra 即规避「证书落错目录」陷阱）
RUN useradd --system --user-group --home-dir /nonexistent \
        --shell /usr/sbin/nologin hydra \
    && mkdir -p /etc/hydra \
    && chown hydra:hydra /etc/hydra \
    && chmod 0750 /etc/hydra
USER hydra
WORKDIR /etc/hydra
# 证书/私钥在此目录持久化（容器重建不换证书，客户端 pinning 不受影响）
VOLUME /etc/hydra
# TCP/TLS 数据面
EXPOSE 443/tcp
ENTRYPOINT ["/usr/local/bin/hydra-node"]
