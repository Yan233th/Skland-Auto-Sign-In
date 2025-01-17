use chrono::Utc;
use reqwest::blocking::Client;

mod tools;
mod verification;

fn main() {
    println!("Current UTC time: {}", Utc::now().format("%Y-%m-%d %H:%M:%S"));
    let tokens = tools::get_tokens();
    let client = Client::new();
    let headers = tools::generate_headers(&client);
    for token in tokens {
        let authorization = tools::get_authorization(&client, &headers, &token);
        let credential = tools::get_credential(&client, &headers, &authorization);
        tools::do_sign(&credential);
    }
    println!();
}
