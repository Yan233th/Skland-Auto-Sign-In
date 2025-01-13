use chrono::Utc;
use tools::get_credential;

mod tools;
mod verification;

fn main() {
    println!("Current UTC time: {}", Utc::now().format("%Y-%m-%d %H:%M:%S"));
    let tokens = tools::get_tokens();
    let headers = tools::generate_headers();
    for token in tokens {
        if token.is_empty() {
            continue;
        }
        get_credential(token, &headers);
    }
}
