use chrono::Utc;
use reqwest::blocking::Client;

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
        let authorization = tools::get_authorization(&client, &headers, &token);
        println!("Got authorization: {}", authorization);
        let credential = tools::get_credential(&client, &headers, &authorization);
        println!("Got credential: {}", credential);
    }
}
