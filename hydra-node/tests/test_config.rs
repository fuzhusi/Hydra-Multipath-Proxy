//! 节点 toml 配置单测：解析 / 分层优先级（CLI > env > file > 默认）/ 非法值显式报错。
//! 全部走 `config::resolve` 纯函数（env 用 BTreeMap 注入，不碰真实进程环境），
//! 离线可测；密钥文件 I/O 用临时文件。

use hydra_node::config::{
    decode_auth_key, load_auth_key, parse_toml, probe_paths, resolve, AuthKeySource, CliOverrides,
    NodeFileConfig,
};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

fn env_of(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn file(text: &str) -> NodeFileConfig {
    parse_toml(text).expect("样例 toml 应可解析")
}

fn cli() -> CliOverrides {
    CliOverrides::default()
}

const FULL_TOML: &str = r#"
listen_addr = "0.0.0.0:9000"
auth_key_file = "/tmp/hydra.key"
max_connections = 500
cert_file = "/tmp/cert.der"
key_file = "/tmp/key.der"
cert_domains = ["a.example", "b.example"]
health_addr = "127.0.0.1:9090"
log_level = "debug"
"#;

#[test]
fn parse_toml_full_document() {
    let f = file(FULL_TOML);
    assert_eq!(f.listen_addr.as_deref(), Some("0.0.0.0:9000"));
    assert_eq!(f.auth_key_file.as_deref(), Some("/tmp/hydra.key"));
    assert_eq!(f.max_connections, Some(500));
    assert_eq!(
        f.cert_domains,
        Some(vec!["a.example".to_string(), "b.example".to_string()])
    );
    assert_eq!(f.health_addr.as_deref(), Some("127.0.0.1:9090"));
    assert_eq!(f.log_level.as_deref(), Some("debug"));
}

#[test]
fn parse_toml_empty_and_unknown_field() {
    // 空文档 = 全 None（全部回落 env/默认）
    let f = parse_toml("").unwrap();
    assert_eq!(f, NodeFileConfig::default());
    // 未知字段显式报错（字段名拼错静默忽略 = 配置黑洞）
    assert!(parse_toml("bogus_field = 1").is_err());
    // 类型错误显式报错
    assert!(parse_toml("max_connections = \"abc\"").is_err());
    assert!(parse_toml("listen_addr = 12345").is_err());
}

const TEST_KEY: &str = "00112233445566778899aabbccddeeff";

#[test]
fn resolve_defaults_when_no_layers() {
    let env = env_of(&[("HYDRA_AUTH_KEY", TEST_KEY)]);
    let r = resolve(&cli(), &env, None).unwrap();
    assert_eq!(r.listen_addr.to_string(), "0.0.0.0:8080");
    assert_eq!(r.max_connections, 1000);
    assert_eq!(r.cert_file, PathBuf::from("hydra-node-cert.der"));
    assert_eq!(r.key_file, PathBuf::from("hydra-node-key.der"));
    assert_eq!(r.cert_domains, vec!["hydra.node", "localhost"]);
    assert_eq!(r.health_addr, None);
    assert_eq!(r.log_level, "info");
    // 没有任何密钥来源 = 显式报错（绝不允许无认证节点启动）
    let err = resolve(&cli(), &env_of(&[]), None).unwrap_err();
    assert!(err.contains("认证密钥"), "报错应指向密钥: {}", err);
}

#[test]
fn resolve_file_layer_applies() {
    let f = file(FULL_TOML);
    let r = resolve(&cli(), &env_of(&[]), Some(&f)).unwrap();
    assert_eq!(r.listen_addr.to_string(), "0.0.0.0:9000");
    assert_eq!(r.max_connections, 500);
    assert_eq!(r.health_addr, Some("127.0.0.1:9090".parse().unwrap()));
    assert_eq!(r.log_level, "debug");
    assert_eq!(
        r.auth_key_source,
        AuthKeySource::File(PathBuf::from("/tmp/hydra.key"))
    );
    assert_eq!(r.cert_domains, vec!["a.example", "b.example"]);
}

#[test]
fn priority_env_over_file() {
    let f = file(FULL_TOML);
    let env = env_of(&[
        ("HYDRA_LISTEN", "0.0.0.0:7000"),
        ("HYDRA_MAX_CONNECTIONS", "42"),
        ("HYDRA_HEALTH_ADDR", "127.0.0.1:7001"),
        ("HYDRA_LOG_LEVEL", "warn"),
        ("HYDRA_AUTH_KEY", "00112233445566778899aabbccddeeff"),
        ("HYDRA_CERT_DOMAINS", "override.example, extra.example"),
    ]);
    let r = resolve(&cli(), &env, Some(&f)).unwrap();
    assert_eq!(r.listen_addr.to_string(), "0.0.0.0:7000");
    assert_eq!(r.max_connections, 42);
    assert_eq!(r.health_addr, Some("127.0.0.1:7001".parse().unwrap()));
    assert_eq!(r.log_level, "warn");
    // env 密钥优先于文件密钥
    assert_eq!(
        r.auth_key_source,
        AuthKeySource::Inline("00112233445566778899aabbccddeeff".to_string())
    );
    assert_eq!(r.cert_domains, vec!["override.example", "extra.example"]);
}

#[test]
fn priority_cli_over_env() {
    let env = env_of(&[
        ("HYDRA_AUTH_KEY", "00112233445566778899aabbccddeeff"),
        ("HYDRA_LISTEN", "0.0.0.0:7000"),
    ]);
    let overrides = CliOverrides {
        listen: Some("127.0.0.1:6000".parse().unwrap()),
    };
    let r = resolve(&overrides, &env, None).unwrap();
    assert_eq!(r.listen_addr.to_string(), "127.0.0.1:6000");
    // CLI 不再承接密钥（--auth-key 已移除）：env 密钥即生效来源
    assert_eq!(
        r.auth_key_source,
        AuthKeySource::Inline("00112233445566778899aabbccddeeff".to_string())
    );
}

#[test]
fn auth_key_source_priority_env_key_beats_env_file_beats_toml_file() {
    let f = file("auth_key_file = \"/tmp/from-toml.key\"");
    // env 两个都设：HYDRA_AUTH_KEY 赢
    let env = env_of(&[
        ("HYDRA_AUTH_KEY", "00112233445566778899aabbccddeeff"),
        ("HYDRA_AUTH_KEY_FILE", "/tmp/from-env.key"),
    ]);
    let r = resolve(&cli(), &env, Some(&f)).unwrap();
    assert_eq!(
        r.auth_key_source,
        AuthKeySource::Inline("00112233445566778899aabbccddeeff".to_string())
    );
    // 只设 HYDRA_AUTH_KEY_FILE：赢过 toml auth_key_file
    let env = env_of(&[("HYDRA_AUTH_KEY_FILE", "/tmp/from-env.key")]);
    let r = resolve(&cli(), &env, Some(&f)).unwrap();
    assert_eq!(
        r.auth_key_source,
        AuthKeySource::File(PathBuf::from("/tmp/from-env.key"))
    );
}

#[test]
fn illegal_values_error_out_explicitly() {
    let f = file(FULL_TOML);
    let cases: Vec<(BTreeMap<String, String>, &str)> = vec![
        (env_of(&[("HYDRA_LISTEN", "not-an-addr")]), "HYDRA_LISTEN"),
        (
            env_of(&[("HYDRA_LISTEN", "example.com:443")]),
            "HYDRA_LISTEN",
        ), // 域名不做解析
        (
            env_of(&[("HYDRA_MAX_CONNECTIONS", "abc")]),
            "HYDRA_MAX_CONNECTIONS",
        ),
        (
            env_of(&[("HYDRA_HEALTH_ADDR", "127.0.0.1")]),
            "HYDRA_HEALTH_ADDR",
        ),
    ];
    for (env, label) in cases {
        let err = resolve(&cli(), &env, Some(&f)).unwrap_err();
        assert!(
            err.contains(label),
            "报错应带来源标签 {}: 得到 {}",
            label,
            err
        );
    }
    // 文件层非法值同样显式报错
    let bad_file = file("listen_addr = \"999.9.9.9:1\"");
    let err = resolve(&cli(), &env_of(&[]), Some(&bad_file)).unwrap_err();
    assert!(
        err.contains("listen_addr"),
        "文件字段报错应带字段名: {}",
        err
    );
}

#[test]
fn probe_paths_order() {
    let p = probe_paths();
    assert_eq!(p[0], PathBuf::from("./node.toml"));
    assert_eq!(p[1], PathBuf::from("/etc/hydra/node.toml"));
}

#[test]
fn resolve_config_path_cli_and_env_and_probe() {
    // CLI 显式路径最优先
    let p = hydra_node::config::resolve_config_path(
        Some(std::path::Path::new("/explicit/node.toml")),
        &env_of(&[("HYDRA_NODE_CONFIG", "/env/node.toml")]),
    );
    assert_eq!(p, Some(PathBuf::from("/explicit/node.toml")));
    // env 次之
    let p = hydra_node::config::resolve_config_path(
        None,
        &env_of(&[("HYDRA_NODE_CONFIG", "/env/node.toml")]),
    );
    assert_eq!(p, Some(PathBuf::from("/env/node.toml")));
    // 未设 = 探测（CI 环境通常都不存在 → None；若开发者目录恰好有 ./node.toml 也能接受）
    let p = hydra_node::config::resolve_config_path(None, &env_of(&[]));
    assert!(p.is_none() || p.as_deref() == Some(std::path::Path::new("./node.toml")));
}

#[test]
fn load_file_layer_explicit_missing_errors() {
    let err = hydra_node::config::load_file_layer(
        Some(std::path::Path::new(
            "Z:/definitely/missing/hydra-node.toml",
        )),
        &env_of(&[]),
    )
    .unwrap_err();
    assert!(
        err.contains("读取配置文件"),
        "显式路径缺失应显式报错: {}",
        err
    );
}

#[test]
fn load_file_layer_from_real_path() {
    // 临时文件走完整 I/O 路径
    let path = std::env::temp_dir().join(format!("hydra-cfg-{}.toml", std::process::id()));
    std::fs::write(&path, FULL_TOML).unwrap();
    let r = hydra_node::config::load_file_layer(Some(&path), &env_of(&[])).unwrap();
    let (p, f) = r.expect("显式存在的文件应加载成功");
    assert_eq!(p, path);
    assert_eq!(f.max_connections, Some(500));
    let _ = std::fs::remove_file(&path);
}

#[test]
fn auth_key_decode_and_file_load() {
    // hex + 长度校验（必须恰好 32 字节：snow NNpsk2 PSK 约束，审查 R-05 fail-fast）
    let k32 = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    assert_eq!(decode_auth_key(k32).unwrap().len(), 32);
    // 16 字节（旧文档曾允许）→ 长度非法
    assert!(decode_auth_key("00112233445566778899aabbccddeeff")
        .unwrap_err()
        .contains("32 字节"));
    assert!(decode_auth_key("0011").unwrap_err().contains("32 字节"));
    assert!(decode_auth_key("zzzz").unwrap_err().contains("hex"));

    // 文件来源（带换行/空白容错）
    let path = std::env::temp_dir().join(format!("hydra-key-{}.txt", std::process::id()));
    std::fs::write(&path, format!("  {k32}\n")).unwrap();
    let key = load_auth_key(&AuthKeySource::File(path.clone())).unwrap();
    assert_eq!(key.len(), 32);
    let _ = std::fs::remove_file(&path);

    // 缺失文件显式报错
    let err = load_auth_key(&AuthKeySource::File(PathBuf::from(
        "Z:/definitely/missing.key",
    )))
    .unwrap_err();
    assert!(err.contains("认证密钥文件"), "{}", err);
}

#[test]
fn env_constant_names_are_stable() {
    assert_eq!(
        hydra_node::config::HYDRA_NODE_CONFIG_ENV,
        "HYDRA_NODE_CONFIG"
    );
    assert_eq!(
        hydra_node::config::HYDRA_AUTH_KEY_FILE_ENV,
        "HYDRA_AUTH_KEY_FILE"
    );
}

#[test]
fn blank_env_values_fall_through_to_next_layer() {
    // 环境变量值为空白 = 该层未设置，回落文件层/默认（与 health_addr_from_env 语义一致）

    // 空白 HYDRA_AUTH_KEY 不应成为密钥来源 → 显式报"未设置密钥"
    let env = env_of(&[("HYDRA_AUTH_KEY", "   ")]);
    let err = resolve(&cli(), &env, None).unwrap_err();
    assert!(err.contains("认证密钥"), "{}", err);
}

#[test]
fn listen_default_is_valid_socket_addr() {
    let env = env_of(&[("HYDRA_AUTH_KEY", TEST_KEY)]);
    let r = resolve(&cli(), &env, None).unwrap();
    assert_eq!(r.listen_addr, SocketAddr::from(([0, 0, 0, 0], 8080)));
}
