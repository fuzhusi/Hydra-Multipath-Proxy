//! Kotlin 绑定生成入口：
//! `cargo run -p hydra-android --bin uniffi-bindgen -- generate \
//!    --library <libhydra_android.so|dll> --language kotlin --out-dir <dir>`
fn main() {
    uniffi::uniffi_bindgen_main()
}
