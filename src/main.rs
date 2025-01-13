use chrono::Utc;
use tools::get_credential;

mod tools;

fn main() {
    println!("Current UTC time: {}", Utc::now().format("%Y-%m-%d %H:%M:%S"));
    let tokens = tools::get_tokens();
    for token in tokens {
        get_credential(token);
    }
}
