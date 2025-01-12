use std::process;
use chrono::Utc;

mod tools;

fn main() {
    println!("Current UTC time: {}", Utc::now().format("%Y-%m-%d %H:%M:%S"));
    // Get user tokens
    let tokens= tools::get_tokens();
    if tokens.is_empty() {
        eprintln!("No user tokens found!");
        process::exit(1);
    }
    else {
        println!("Get user tokens successfully!")
    }
}
