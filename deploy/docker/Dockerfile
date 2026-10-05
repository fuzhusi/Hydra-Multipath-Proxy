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
# 依赖缓存层（审查 R-25 收尾）：先只拷各 Cargo.toml + 虚 src 做 cargo fetch，
# 源码不变时依赖层直接命中，源码变更不必全量重编
COPY Cargo.toml Cargo.lock ./
COPY hydra-protocol/Cargo.toml hydra-protocol/Cargo.toml
COPY hydra-node/Cargo.toml hydra-node/Cargo.toml
COPY hydra-client/Cargo.toml hydra-client/Cargo.toml
COPY hydra-client-gui/Cargo.toml hydra-client-gui/Cargo.toml
RUN mkdir -p hydra-protocol/src hydra-node/src hydra-client/src hydra-client-gui/src \
    && echo "pub fn placeholder() {}" > hydra-protocol/src/lib.rs \
    && echo "fn main() {}" > hydra-node/src/main.rs \
    && echo "fn main() {}" > hydra-client/src/main.rs \
    && echo "pub fn placeholder() {}" > hydra-client/src/lib.rs \
    && echo "fn main() {}" > hydra-client-gui/src/main.rs \
    && cargo fetch
# 全量源码（.dockerignore 已排除 target/.probe/.e2e/*.der 等体积与敏感物）
COPY . .
# 触碰虚文件的时间戳使依赖层产物仍可用（cargo 以 mtime+内容判断重编）
RUN find hydra-* -name "*.rs" -not -path "*/tests/*" -exec touch {} + \
    && cargo build --release -p hydra-node

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
