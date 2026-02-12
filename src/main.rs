mod checks;
mod report;

use checks::*;
use report::*;

fn main() {
    println!("Linux Guardian - Security Scan\n");

    let mut results = Vec::new();

    results.push(check_ssh_root_login());

    for result in &results {
        println!("{}: {}", result.name, result.message);
    }

    let score = calculate_score(&results);
    let grade = grade(score);

    println!("\nSecurity Score: {}/100", score);
    println!("Grade: {}", grade);
}

