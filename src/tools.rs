use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{env, fs};

#[derive(Deserialize, Serialize)]
pub struct ResponseData {
    pub status: i32,
    pub message: String,
    pub data: serde_json::Value,
}

pub fn get_tokens() -> Vec<String> {
    let tokens: Vec<String> = match env::var("USER_TOKENS") {
        Ok(val) => val.split(';').map(|s| s.trim().to_string()).collect(),
        Err(_) => {
            println!("The USER_TOKENS variable was not found in the environment variables, attempting to read from user_tokens.txt.");
            match fs::read_to_string("user_tokens.txt") {
                Ok(val) => val.split('\n').map(|s| s.trim().to_string()).collect(),
                Err(_) => panic!("Unable to find USER_TOKENS environment variable or user_tokens.txt file!"),
            }
        }
    };
    if tokens.is_empty() {
        panic!("No user tokens found!");
    } else {
        println!("Get user tokens successfully!")
    }
    return tokens;
}

pub fn get_credential(token: String) {
    let client = Client::new();
    let authorization_code_response: ResponseData = client
        .post("https://as.hypergryph.com/user/oauth2/v2/grant")
        .json(&json!({ "appCode": "4ca99fa6b56cc2ba", "token": token, "type": 0 }))
        .send()
        .unwrap()
        .json()
        .unwrap();
    if authorization_code_response.status != 0 {
        panic!("Failed to get cred: {}", authorization_code_response.message)
    }
}
