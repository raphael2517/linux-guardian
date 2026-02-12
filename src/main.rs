mod checks;
mod report;

use checks::*;
use report::*;

fn main() {
    println!("Linux Guardian - Security Scan\n");

    let mut results = Vec::new();

    results.push(check_ssh_root_login());
    results.push(check_ssh_password_auth());
    results.push(check_firewall_status());

    for result in &results {
        println!("{} [{:?}]: {}", result.name, result.risk, result.message);
    }

    let score = calculate_score(&results);
    let final_grade = grade(score);

    println!("\nSecurity Score: {}/100", score);
    println!("Grade: {}", final_grade);
}
