use reqwest::{
    blocking::Client,
    header::{HeaderMap, HeaderValue},
};
use serde_json::json;
use std::{env, fs};

use crate::verification;

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

pub fn generate_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("User-Agent", HeaderValue::from_static("Skland/1.0.1 (com.hypergryph.skland; build:100001014; Android 31; ) Okhttp/4.11.0"));
    headers.insert("Accept-Encoding", HeaderValue::from_static("gzip"));
    headers.insert("Connection", HeaderValue::from_static("close"));
    // headers.insert("dId", HeaderValue::from_str(&verification::get_did()).unwrap());
    return headers;
}

pub fn get_credential(client: &Client, headers: &HeaderMap, token: &str) {}

pub fn get_authorization_code(client: &Client, headers: &HeaderMap, token: &str) -> String {
    let authorization_code_response: serde_json::Value = client
        .post("https://as.hypergryph.com/user/oauth2/v2/grant")
        .headers(headers.clone())
        .json(&json!({ "appCode": "4ca99fa6b56cc2ba", "token": token, "type": 0 }))
        .send()
        .unwrap()
        .json()
        .unwrap();
    if authorization_code_response["status"] != 0 {
        panic!("Failed to get credential: {}", authorization_code_response["message"])
    }
    return authorization_code_response["data"]["code"].as_str().unwrap().to_string();
}
