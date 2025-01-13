use chrono::Utc;

mod tools;

fn main() {
    println!("Current UTC time: {}", Utc::now().format("%Y-%m-%d %H:%M:%S"));
    let tokens = tools::get_tokens();
    for token in tokens {
        // panic!("123")
    }
}
