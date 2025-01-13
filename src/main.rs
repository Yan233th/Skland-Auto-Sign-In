use chrono::Utc;
use tools::get_credential;

mod tools;

fn main() {
    println!("Current UTC time: {}", Utc::now().format("%Y-%m-%d %H:%M:%S"));
    let tokens = tools::get_tokens();
    for token in tokens {
        if token.is_empty() {
            continue;
        }
        get_credential(token);
    }
}
