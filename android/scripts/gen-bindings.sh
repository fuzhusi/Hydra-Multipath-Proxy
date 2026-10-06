#!/usr/bin/env bash
# 再生成 uniffi Kotlin 绑定 → android/app/src/main/kotlin/uniffi/hydra_android/
# 用法：在仓库根执行 bash android/scripts/gen-bindings.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

cargo build -p hydra-android
cargo run -p hydra-android --bin uniffi-bindgen -- generate \
    --library target/debug/hydra_android.dll \
    --language kotlin \
    --out-dir android/app/src/main/kotlin \
    --no-format
echo "[gen-bindings] 完成：android/app/src/main/kotlin/uniffi/hydra_android/"
