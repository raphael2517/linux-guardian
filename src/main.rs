mod checks;

fn main() {
    println!("Linux Guardian - Security Scan\n");

    let ssh_result = checks::check_ssh_root_login();
    println!("{}", ssh_result);
}

