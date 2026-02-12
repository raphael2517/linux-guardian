mod checks;

fn main() {
    println!("Linux Guardian - Security Scan\n");

    let ssh_root = checks::check_ssh_root_login();
    let ssh_password = checks::check_ssh_password_auth();
    let firewall = checks::check_firewall_status();

    println!("{}", ssh_root);
    println!("{}", ssh_password);
    println!("{}", firewall);
}

