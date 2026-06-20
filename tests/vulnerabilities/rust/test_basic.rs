fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    std::process::Command::new("sh").arg("-c").arg(&cmd).status();
}
