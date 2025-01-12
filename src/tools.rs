use std::{env, fs, process};

pub fn get_tokens() -> Vec<String> {
    return match env::var("USER_TOKENS") {
        Ok(val) => val.split(';').map(|s| s.trim().to_string()).collect(),
        Err(_) => {
            println!("The USER_TOKENS variable was not found in the environment variables, attempting to read from user_tokens.txt.");
            match fs::read_to_string("user_tokens.txt") {
                Ok(val) => val.split('\n').map(|s| s.trim().to_string()).collect(),
                Err(_) => {
                    eprintln!("Unable to find USER_TOKENS environment variable or user_tokens.txt file!");
                    process::exit(1);
                }
            }
        }
    };
}