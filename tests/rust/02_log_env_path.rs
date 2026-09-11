// Rust Log Injection, Env Injection, Path Traversal Tests

fn main() {
    let user_input = std::env::args().nth(1).unwrap_or_default();
    let file_path = std::env::args().nth(2).unwrap_or_default();

    // CVI_9507 - 日志注入
    log::info!("User request: {}", user_input);
    log::warn!("Suspicious input: {}", user_input);
    log::error!("Error with input: {}", user_input);
    log::debug!("Debug: {}", user_input);

    // CVI_9509 - 环境变量注入
    std::env::set_var("USER_INPUT", &user_input);
    env::set_var("CONFIG", &user_input);
    set_var("DATA", &user_input);

    // CVI_9510 - 不安全随机数
    let mut rng = rand::thread_rng();
    let n: u32 = rand::random();
    let r = thread_rng();

    // CVI_9511 - 路径遍历
    let mut path = PathBuf::new();
    path.push(&file_path);
    let p = Path::new(&file_path);
    let full = PathBuf::from("/var/data").join(&file_path);

    // False positives
    log::info!("Server started");
    std::env::set_var("APP_ENV", "production");
    Path::new("/etc/passwd");
}
