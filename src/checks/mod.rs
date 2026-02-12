use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

pub fn check_ssh_root_login() -> String {
    let path = "/etc/ssh/sshd_config";

    if !Path::new(path).exists() {
        return "[!] SSH config not found".to_string();
    }

    let file = File::open(path);
    if file.is_err() {
        return "[!] Unable to read SSH config (try running with sudo)".to_string();
    }

    let reader = io::BufReader::new(file.unwrap());

    for line in reader.lines() {
        if let Ok(content) = line {
            let trimmed = content.trim();

            // Ignore commented lines
            if trimmed.starts_with('#') {
                continue;
            }

            if trimmed.starts_with("PermitRootLogin") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    match parts[1] {
                        "yes" => return "[!] SSH Root Login Enabled (HIGH RISK)".to_string(),
                        "no" => return "[✓] SSH Root Login Disabled".to_string(),
                        "prohibit-password" => {
                            return "[!] Root login allowed via key (MEDIUM RISK)".to_string()
                        }
                        _ => return "[?] Unknown SSH root login setting".to_string(),
                    }
                }
            }
        }
    }

    "[?] PermitRootLogin not explicitly set (check defaults)".to_string()
}
