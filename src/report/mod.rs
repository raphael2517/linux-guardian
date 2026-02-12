use crate::checks::CheckResult;

pub fn calculate_score(results: &Vec<CheckResult>) -> i32 {
    let mut score = 100;

    for result in results {
        score -= result.score_impact;
    }

    if score < 0 {
        0
    } else {
        score
    }
}

pub fn grade(score: i32) -> &'static str {
    match score {
        90..=100 => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
    }
}
