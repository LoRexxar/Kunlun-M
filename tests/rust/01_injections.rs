use std::process::Command;
use std::fs;
use std::env;

fn main() {
    let user_input = env::args().nth(1).unwrap_or_default();
    let filename = env::args().nth(2).unwrap_or_default();

    // 漏洞 - 命令注入
    let _ = Command::new("sh").arg("-c").arg(&user_input).status();

    // 漏洞 - 路径遍历
    let _ = fs::read_to_string(&filename);
    let _ = fs::write(&filename, "data");
    let _ = fs::remove_file(&filename);

    // 漏洞 - 反序列化
    let _ : serde_json::Value = serde_json::from_str(&user_input).unwrap();

    // 安全
    let _ = Command::new("ls").status();
    let _ = fs::read_to_string("config.toml");
    let _ = fs::remove_file("/tmp/cache");
}
