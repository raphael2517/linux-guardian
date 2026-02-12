# Linux Guardian

Linux Guardian is a modular Linux security and system auditing tool written in Rust.

It analyzes critical system configurations, evaluates risk exposure, and generates a weighted security score with grading. The project is designed with clean architecture and extensibility in mind.

## Features

- SSH Root Login detection (`PermitRootLogin`)
- SSH Password Authentication analysis
- Firewall status validation (`ufw`, `firewalld`)
- Structured risk modeling (Low / Medium / High)
- Weighted security scoring system
- Letter-grade system evaluation (A–F)


## Example Output
---
Linux Guardian - Security Scan

SSH Root Login [Medium]: Root login allowed via key
SSH Password Authentication [Medium]: Setting not explicitly defined
Firewall Status [Low]: firewalld active

Security Score: 85/100
Grade: B
---

## Architecture

src/
├── main.rs
├── checks/
│ └── mod.rs
└── report/
└── mod.rs


- Modular check system
- Structured `CheckResult` return type
- Centralized scoring engine
- Clean separation between scanning and reporting

---
## Installation
git clone https://github.com/raphael2517/linux-guardian.git
cd linux-guardian
cargo build --release
---

Run:

---
cargo run
---

Some checks may require:

--- 
sudo cargo run
---


## Roadmap

Open port scanning
SUID binary auditing
World-writable directory detection
Kernel parameter analysis
JSON output mode
CLI argument support
