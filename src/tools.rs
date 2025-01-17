use reqwest::{
    blocking::Client,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use serde_json::{json, Value};
use std::{env, fs};
use url::Url;

use crate::verification;

pub fn get_tokens() -> Vec<String> {
    let tokens: Vec<String> = match env::var("USER_TOKENS") {
        Ok(val) => val.split(';').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        Err(_) => {
            println!("The USER_TOKENS variable was not found in the environment variables, attempting to read from user_tokens.txt.");
            match fs::read_to_string("user_tokens.txt") {
                Ok(val) => val.split('\n').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
                Err(_) => panic!("Unable to find USER_TOKENS environment variable or user_tokens.txt file!"),
            }
        }
    };
    if tokens.is_empty() {
        panic!("No user tokens found!");
    } else {
        println!("Got {} user tokens successfully!", tokens.len());
    }
    return tokens;
}

pub fn generate_headers(client: &Client) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("User-Agent", HeaderValue::from_static("Skland/1.0.1 (com.hypergryph.skland; build:100001014; Android 31; ) Okhttp/4.11.0"));
    headers.insert("Accept-Encoding", HeaderValue::from_static("gzip"));
    headers.insert("Connection", HeaderValue::from_static("close"));
    headers.insert("dId", HeaderValue::from_str(&verification::get_did(client)).unwrap());
    return headers;
}

pub fn get_authorization(client: &Client, headers: &HeaderMap, token: &str) -> String {
    let authorization_response: Value = client
        .post("https://as.hypergryph.com/user/oauth2/v2/grant")
        .headers(headers.clone())
        .json(&json!({"appCode": "4ca99fa6b56cc2ba", "token": token, "type": 0}))
        .send()
        .unwrap()
        .json()
        .unwrap();
    if authorization_response["status"] != 0 {
        panic!("Failed to get authorization: {}", authorization_response["message"]);
    }
    return authorization_response["data"]["code"].as_str().expect("Not a String!").to_string();
}

pub fn get_credential(client: &Client, headers: &HeaderMap, authorization: &str) -> Value {
    let credential_response: Value = client
        .post("https://zonai.skland.com/web/v1/user/auth/generate_cred_by_code")
        .headers(headers.clone())
        .json(&json!({"code": authorization, "kind": 1}))
        .send()
        .unwrap()
        .json()
        .unwrap();
    if credential_response["code"] != 0 {
        panic!("Failed to get credential: {}", credential_response["message"]);
    }
    return credential_response["data"].clone();
}

pub fn do_sign(cred_resp: &Value) {
    let http_token = cred_resp["token"].as_str().unwrap();
    let cred = cred_resp["cred"].as_str().unwrap();
    let mut http_header = HeaderMap::new();
    http_header.insert("User-Agent", HeaderValue::from_static("Skland/1.0.1 (com.hypergryph.skland; build:100001014; Android 31; ) Okhttp/4.11.0"));
    http_header.insert("Accept-Encoding", HeaderValue::from_static("gzip"));
    http_header.insert("Connection", HeaderValue::from_static("close"));
    http_header.insert("cred", HeaderValue::from_str(cred).unwrap());
    let client = Client::new();
    let characters = get_binding_list(&http_header, http_token);
    for character in characters {
        let nick_name = character["nickName"].as_str().unwrap_or("Unknown");
        let channel_name = character["channelName"].as_str().unwrap_or("Unknown");
        let body = json!({"gameId": 1, "uid": character["uid"].as_str().unwrap()});
        let headers = get_sign_header("https://zonai.skland.com/api/v1/game/attendance", "post", Some(body.to_string().as_str()), &http_header, http_token);
        let resp: Value = client.post("https://zonai.skland.com/api/v1/game/attendance").headers(headers).json(&body).send().unwrap().json().unwrap();
        if resp["code"].as_i64().unwrap() != 0 {
            eprintln!("Character {}({}) sign-in failed! Reason: {}", nick_name, channel_name, resp["message"].as_str().unwrap_or("Unknown error"));
            continue;
        }
        for award in resp["data"]["awards"].as_array().unwrap() {
            let name = award["resource"]["name"].as_str().unwrap_or("Unknown");
            let count = award["count"].as_i64().unwrap_or(1);
            println!("Character {}({}) signed in successfully and received {}*{}.", nick_name, channel_name, name, count);
        }
    }
}

fn get_binding_list(http_header: &HeaderMap, http_token: &str) -> Vec<Value> {
    let client = reqwest::blocking::Client::new();
    let sign_header = get_sign_header("https://zonai.skland.com/api/v1/game/player/binding", "get", None, http_header, http_token);
    let resp: Value = client.get("https://zonai.skland.com/api/v1/game/player/binding").headers(sign_header).send().unwrap().json().unwrap();
    if resp["code"] != 0 {
        eprintln!("An issue occurred while requesting the character list.: {}", resp["message"]);
        if resp["message"] == "用户未登录" {
            eprintln!("User login may have expired. Please rerun this program!");
        }
        return vec![];
    }
    let mut binding_list = Vec::new();
    for i in resp["data"]["list"].as_array().unwrap() {
        if i["appCode"].as_str().unwrap() != "arknights" {
            continue;
        }
        binding_list.extend(i["bindingList"].as_array().unwrap().to_vec());
    }
    return binding_list;
}

fn get_sign_header(url: &str, method: &str, body: Option<&str>, header: &HeaderMap, token: &str) -> HeaderMap {
    let parsed_url = Url::parse(url).expect("Invalid URL");
    let (sign, header_ca) = if method.to_lowercase() == "get" {
        let query = parsed_url.query().unwrap_or("");
        verification::generate_signature(token, parsed_url.path(), query)
    } else {
        verification::generate_signature(token, parsed_url.path(), body.unwrap_or(""))
    };
    let mut header_clone = header.clone();
    header_clone.insert("sign", sign.parse().unwrap());
    for (key, value) in header_ca {
        header_clone.insert(
            HeaderName::from_bytes(key.as_bytes()).unwrap(),
            match value {
                Value::Number(num) => HeaderValue::from_str(&num.to_string()).unwrap(),
                Value::String(s) => HeaderValue::from_str(&s).unwrap(),
                _ => panic!("Unexpected value type: {:?}", value),
            },
        );
    }
    return header_clone;
}
