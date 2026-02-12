#[derive(Debug)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

pub struct CheckResult {
    pub name: String,
    pub risk: RiskLevel,
    pub message: String,
    pub score_impact: i32,
}


use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

pub fn check_ssh_root_login() -> CheckResult {
    let path = "/etc/ssh/sshd_config";

    if !Path::new(path).exists() {
        return CheckResult {
            name: "SSH Root Login".to_string(),
            risk: RiskLevel::High,
            message: "SSH config not found".to_string(),
            score_impact: 20,
        };
    }

    let file = File::open(path);
    if file.is_err() {
        return CheckResult {
            name: "SSH Root Login".to_string(),
            risk: RiskLevel::High,
            message: "Cannot read SSH config (run as sudo)".to_string(),
            score_impact: 20,
        };
    }

    let reader = io::BufReader::new(file.unwrap());

    for line in reader.lines() {
        if let Ok(content) = line {
            let trimmed = content.trim();

            if trimmed.starts_with('#') {
                continue;
            }

            if trimmed.starts_with("PermitRootLogin") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    match parts[1] {
                        "yes" => {
                            return CheckResult {
                                name: "SSH Root Login".to_string(),
                                risk: RiskLevel::High,
                                message: "Root login enabled".to_string(),
                                score_impact: 25,
                            }
                        }
                        "no" => {
                            return CheckResult {
                                name: "SSH Root Login".to_string(),
                                risk: RiskLevel::Low,
                                message: "Root login disabled".to_string(),
                                score_impact: 0,
                            }
                        }
                        "prohibit-password" => {
                            return CheckResult {
                                name: "SSH Root Login".to_string(),
                                risk: RiskLevel::Medium,
                                message: "Root login allowed via key".to_string(),
                                score_impact: 10,
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    CheckResult {
        name: "SSH Root Login".to_string(),
        risk: RiskLevel::Medium,
        message: "Setting not explicitly defined".to_string(),
        score_impact: 10,
    }
}


pub fn check_ssh_password_auth() -> String {
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

            if trimmed.starts_with('#') {
                continue;
            }

            if trimmed.starts_with("PasswordAuthentication") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    match parts[1] {
                        "yes" => {
                            return "[!] SSH Password Authentication Enabled (MEDIUM RISK)"
                                .to_string()
                        }
                        "no" => {
                            return "[✓] SSH Password Authentication Disabled (Key-only login)"
                                .to_string()
                        }
                        _ => return "[?] Unknown SSH password authentication setting".to_string(),
                    }
                }
            }
        }
    }

    "[?] PasswordAuthentication not explicitly set".to_string()
}


use std::process::Command;

pub fn check_firewall_status() -> String {
    // Check UFW
    let ufw = Command::new("ufw").arg("status").output();

    if let Ok(output) = ufw {
        let result = String::from_utf8_lossy(&output.stdout);
        if result.contains("Status: active") {
            return "[✓] UFW Firewall Active".to_string();
        } else if result.contains("Status: inactive") {
            return "[!] UFW Installed but Inactive (RISK)".to_string();
        }
    }

    // Check firewalld
    let firewalld = Command::new("systemctl")
        .arg("is-active")
        .arg("firewalld")
        .output();

    if let Ok(output) = firewalld {
        let result = String::from_utf8_lossy(&output.stdout);
        if result.contains("active") {
            return "[✓] firewalld Active".to_string();
        }
    }

    // Fallback check for iptables rules
    let iptables = Command::new("iptables").arg("-L").output();
    if let Ok(output) = iptables {
        if !output.stdout.is_empty() {
            return "[?] iptables present (manual verification needed)".to_string();
        }
    }

    "[!] No Active Firewall Detected".to_string()
}



