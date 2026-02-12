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


pub fn check_ssh_password_auth() -> CheckResult {
    let path = "/etc/ssh/sshd_config";

    if !Path::new(path).exists() {
        return CheckResult {
            name: "SSH Password Authentication".to_string(),
            risk: RiskLevel::High,
            message: "SSH config not found".to_string(),
            score_impact: 15,
        };
    }

    let file = File::open(path);
    if file.is_err() {
        return CheckResult {
            name: "SSH Password Authentication".to_string(),
            risk: RiskLevel::High,
            message: "Cannot read SSH config (run as sudo)".to_string(),
            score_impact: 15,
        };
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
                            return CheckResult {
                                name: "SSH Password Authentication".to_string(),
                                risk: RiskLevel::Medium,
                                message: "Password authentication enabled".to_string(),
                                score_impact: 10,
                            }
                        }
                        "no" => {
                            return CheckResult {
                                name: "SSH Password Authentication".to_string(),
                                risk: RiskLevel::Low,
                                message: "Password authentication disabled (key-only)".to_string(),
                                score_impact: 0,
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    CheckResult {
        name: "SSH Password Authentication".to_string(),
        risk: RiskLevel::Medium,
        message: "Setting not explicitly defined".to_string(),
        score_impact: 5,
    }
}




pub fn check_firewall_status() -> CheckResult {
    use std::process::Command;

    // Check UFW
    if let Ok(output) = Command::new("ufw").arg("status").output() {
        let result = String::from_utf8_lossy(&output.stdout);
        if result.contains("Status: active") {
            return CheckResult {
                name: "Firewall Status".to_string(),
                risk: RiskLevel::Low,
                message: "UFW firewall active".to_string(),
                score_impact: 0,
            };
        } else if result.contains("Status: inactive") {
            return CheckResult {
                name: "Firewall Status".to_string(),
                risk: RiskLevel::High,
                message: "UFW installed but inactive".to_string(),
                score_impact: 20,
            };
        }
    }

    // Check firewalld
    if let Ok(output) = Command::new("systemctl")
        .arg("is-active")
        .arg("firewalld")
        .output()
        {
            let result = String::from_utf8_lossy(&output.stdout);
            if result.contains("active") {
                return CheckResult {
                    name: "Firewall Status".to_string(),
                    risk: RiskLevel::Low,
                    message: "firewalld active".to_string(),
                    score_impact: 0,
                };
            }
        }

        // Fallback: no firewall detected
        CheckResult {
            name: "Firewall Status".to_string(),
            risk: RiskLevel::High,
            message: "No active firewall detected".to_string(),
            score_impact: 25,
        }
}


