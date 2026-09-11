use std::process::Command;

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    // Rust: direct call through variable binding
    let output = Command::new("sh").arg("-c").arg(&cmd).output();
    println!("{:?}", output);
}
