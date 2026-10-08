#!/usr/bin/env bash
# 再生成 uniffi Kotlin 绑定 → android/app/src/main/kotlin/uniffi/hydra_android/
# 用法：在仓库根执行 bash android/scripts/gen-bindings.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

# M2 起 VPN FFI（start_vpn/stop_vpn）为 target_os=android 专属——绑定必须从
# Android .so 生成（桌面 dll 生成会缺失 VPN 接口）。cargo-ndk debug 构建即可。
cargo ndk -t arm64-v8a build -p hydra-android
cargo run -p hydra-android --bin uniffi-bindgen -- generate \
    --library target/aarch64-linux-android/debug/libhydra_android.so \
    --language kotlin \
    --out-dir android/app/src/main/kotlin \
    --no-format
echo "[gen-bindings] 完成：android/app/src/main/kotlin/uniffi/hydra_android/"
