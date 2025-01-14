use chrono::Utc;
use reqwest::blocking::Client;
use tools::get_credential;

mod tools;
mod verification;

fn main() {
    println!("Current UTC time: {}", Utc::now().format("%Y-%m-%d %H:%M:%S"));
    let tokens = tools::get_tokens();
    let headers = tools::generate_headers();
    let client = Client::new();
    for token in tokens {
        if token.is_empty() {
            continue;
        }
        let authorization_code = tools::get_authorization_code(&client, &headers, &token);
        println!("Got code: {}", authorization_code);
        get_credential(&client, &headers, &token);
    }
}
