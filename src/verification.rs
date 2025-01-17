use base64::{engine::general_purpose, Engine};
use chrono::Local;
use flate2::{write::GzEncoder, Compression};
use hex;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use openssl::{
    rsa::Rsa,
    symm::{Cipher, Crypter, Mode},
};
use reqwest::blocking::Client;
use serde_json::{json, Map, Value};
use sha2::Sha256;
use std::{
    collections::HashMap,
    io::prelude::Write,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const DES_RULE: &str = r#"{
    "appId": {"cipher": "DES", "is_encrypt": 1, "key": "uy7mzc4h", "obfuscated_name": "xx"},
    "box": {"is_encrypt": 0, "obfuscated_name": "jf"},
    "canvas": {"cipher": "DES", "is_encrypt": 1, "key": "snrn887t", "obfuscated_name": "yk"},
    "clientSize": {"cipher": "DES", "is_encrypt": 1, "key": "cpmjjgsu", "obfuscated_name": "zx"},
    "organization": {"cipher": "DES", "is_encrypt": 1, "key": "78moqjfc", "obfuscated_name": "dp"},
    "os": {"cipher": "DES", "is_encrypt": 1, "key": "je6vk6t4", "obfuscated_name": "pj"},
    "platform": {"cipher": "DES", "is_encrypt": 1, "key": "pakxhcd2", "obfuscated_name": "gm"},
    "plugins": {"cipher": "DES", "is_encrypt": 1, "key": "v51m3pzl", "obfuscated_name": "kq"},
    "pmf": {"cipher": "DES", "is_encrypt": 1, "key": "2mdeslu3", "obfuscated_name": "vw"},
    "protocol": {"is_encrypt": 0, "obfuscated_name": "protocol"},
    "referer": {"cipher": "DES", "is_encrypt": 1, "key": "y7bmrjlc", "obfuscated_name": "ab"},
    "res": {"cipher": "DES", "is_encrypt": 1, "key": "whxqm2a7", "obfuscated_name": "hf"},
    "rtype": {"cipher": "DES", "is_encrypt": 1, "key": "x8o2h2bl", "obfuscated_name": "lo"},
    "sdkver": {"cipher": "DES", "is_encrypt": 1, "key": "9q3dcxp2", "obfuscated_name": "sc"},
    "status": {"cipher": "DES", "is_encrypt": 1, "key": "2jbrxxw4", "obfuscated_name": "an"},
    "subVersion": {"cipher": "DES", "is_encrypt": 1, "key": "eo3i2puh", "obfuscated_name": "ns"},
    "svm": {"cipher": "DES", "is_encrypt": 1, "key": "fzj3kaeh", "obfuscated_name": "qr"},
    "time": {"cipher": "DES", "is_encrypt": 1, "key": "q2t3odsk", "obfuscated_name": "nb"},
    "timezone": {"cipher": "DES", "is_encrypt": 1, "key": "1uv05lj5", "obfuscated_name": "as"},
    "tn": {"cipher": "DES", "is_encrypt": 1, "key": "x9nzj1bp", "obfuscated_name": "py"},
    "trees": {"cipher": "DES", "is_encrypt": 1, "key": "acfs0xo4", "obfuscated_name": "pi"},
    "ua": {"cipher": "DES", "is_encrypt": 1, "key": "k92crp1t", "obfuscated_name": "bj"},
    "url": {"cipher": "DES", "is_encrypt": 1, "key": "y95hjkoo", "obfuscated_name": "cf"},
    "version": {"is_encrypt": 0, "obfuscated_name": "version"},
    "vpw": {"cipher": "DES", "is_encrypt": 1, "key": "r9924ab5", "obfuscated_name": "ca"}
}"#;

const DES_TARGET: &str = r#"{
    "protocol": 102,
    "organization": "UWXspnCCJN4sfYlNfqps",
    "appId": "default",
    "os": "web",
    "version": "3.0.0",
    "sdkver": "3.0.0",
    "box": "",
    "rtype": "all",
    "subVersion": "1.0.0",
    "time": 0
}"#;

const BROWSER_ENV: &str = r#"{
    "plugins": "MicrosoftEdgePDFPluginPortableDocumentFormatinternal-pdf-viewer1,MicrosoftEdgePDFViewermhjfbmdgcfjbbpaeojofohoefgiehjai1",
    "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
    "canvas": "259ffe69",
    "timezone": -480,
    "platform": "Win32",
    "url": "https://www.skland.com/",
    "referer": "",
    "res": "1920_1080_24_1.25",
    "clientSize": "0_0_1080_1920_1920_1080_1920_1080",
    "status": "0011"
}"#;

pub fn get_did(client: &Client) -> String {
    let browser_env: Map<String, Value> = serde_json::from_str(BROWSER_ENV).unwrap();
    let des_rules: HashMap<String, HashMap<String, Value>> = serde_json::from_str(DES_RULE).unwrap();
    let uid = Uuid::new_v4().to_string();
    let pri_id_hash = Md5::digest(uid.as_bytes());
    let pri_id = &pri_id_hash[0..8];
    let pri_id_hex = pri_id.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let public_key = general_purpose::STANDARD
        .decode("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmxMNr7n8ZeT0tE1R9j/mPixoinPkeM+k4VGIn/s0k7N5rJAfnZ0eMER+QhwFvshzo0LNmeUkpR8uIlU/GEVr8mN28sKmwd2gpygqj0ePnBmOW4v0ZVwbSYK+izkhVFk2V/doLoMbWy6b+UnA8mkjvg0iYWRByfRsK2gdl7llqCwIDAQAB")
        .unwrap();
    let rsa = Rsa::public_key_from_der(&public_key).unwrap();
    let mut ep = vec![0; rsa.size() as usize];
    let ep_len = rsa.public_encrypt(uid.as_bytes(), &mut ep, openssl::rsa::Padding::PKCS1).unwrap();
    ep.truncate(ep_len);
    let ep_base64 = general_purpose::STANDARD.encode(&ep);
    let since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards");
    let in_ms = since_the_epoch.as_millis();
    let mut browser = browser_env.clone();
    browser.insert("vpw".to_string(), json!(Uuid::new_v4()));
    browser.insert("trees".to_string(), json!(Uuid::new_v4()));
    browser.insert("svm".to_string(), json!(in_ms));
    browser.insert("pmf".to_string(), json!(in_ms));
    let mut des_target: Map<String, Value> = serde_json::from_str(DES_TARGET).unwrap();
    des_target.insert("smid".to_string(), json!(get_smid()));
    for (key, value) in browser.iter() {
        des_target.insert(key.clone(), json!(value));
    }
    des_target.insert("tn".to_string(), json!(format!("{:x}", Md5::digest(get_tn(&des_target).as_bytes()))));
    let compressed_data = gzip_compress(&apply_des_rules(&des_target, &des_rules));
    let encrypted = aes_encrypt(&compressed_data, pri_id_hex.as_bytes());
    // println!("Final: {}", encrypted);
    let response: Value = client
        .post("https://fp-it.portal101.cn/deviceprofile/v4")
        .json(&json!({
            "appId": "default",
            "compress": 2,
            "data": encrypted,
            "encode": 5,
            "ep": ep_base64,
            "organization": "UWXspnCCJN4sfYlNfqps",
            "os": "web"
        }))
        .send()
        .unwrap()
        .json()
        .unwrap();
    if response["code"] != 1100 {
        eprintln!("{}", response);
        panic!("D_ID calculation failed!");
    }
    return format!("B{}", response["detail"]["deviceId"].as_str().unwrap());
}

fn des_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    use cipher::{
        generic_array::GenericArray,
        {BlockEncrypt, KeyInit},
    };
    use des::TdesEde3;
    let mut buffer = data.to_vec();
    // Pad with null bytes to a multiple of 8 bytes, and pad at least 8 bytes
    let padding_len = 8 - (buffer.len() % 8);
    buffer.extend(vec![0; padding_len]);
    // Convert to a 24-byte key for Triple DES
    let key_24: [u8; 24] = {
        let mut key_24 = [0u8; 24];
        let key_len = key.len();
        for i in 0..24 {
            key_24[i] = key[i % key_len];
        }
        key_24
    };
    let cipher = TdesEde3::new_from_slice(&key_24).expect("Invalid Triple DES key");
    let mut result = Vec::new();
    for block in buffer.chunks(8) {
        let mut block_arr = GenericArray::clone_from_slice(block);
        cipher.encrypt_block(&mut block_arr);
        result.extend_from_slice(block_arr.as_slice());
    }
    return result;
}

fn apply_des_rules(input: &Map<String, Value>, rules: &HashMap<String, HashMap<String, Value>>) -> Map<String, Value> {
    let mut result = Map::new();
    for (key, value) in input.iter() {
        let string_value = match value.as_str() {
            Some(s) => s.to_string(),
            None => value.to_string(),
        };
        if let Some(rule) = rules.get(key) {
            if let Some(is_encrypt) = rule.get("is_encrypt").and_then(|v| v.as_i64()) {
                if is_encrypt == 1 {
                    if let (Some(key_str), Some(obfuscated_name)) = (rule.get("key").and_then(|v| v.as_str()), rule.get("obfuscated_name").and_then(|v| v.as_str())) {
                        let key = key_str.as_bytes();
                        let data = string_value.as_bytes();
                        let encrypted = des_encrypt(key, data);
                        result.insert(obfuscated_name.to_string(), Value::String(general_purpose::STANDARD.encode(&encrypted)));
                    } else {
                        result.insert(key.clone(), value.clone());
                    }
                } else if let Some(obfuscated_name) = rule.get("obfuscated_name").and_then(|v| v.as_str()) {
                    result.insert(obfuscated_name.to_string(), value.clone());
                } else {
                    result.insert(key.clone(), value.clone());
                }
            } else {
                result.insert(key.clone(), value.clone());
            }
        } else {
            result.insert(key.clone(), value.clone());
        }
    }
    return result;
}

fn gzip_compress(input: &Map<String, Value>) -> Vec<u8> {
    let json_str = serde_json::to_string(input).unwrap();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(2));
    encoder.write_all(json_str.as_bytes()).unwrap();
    return encoder.finish().expect("Failed to finish compression");
}

fn get_tn(data: &Map<String, Value>) -> String {
    let mut sorted_keys: Vec<_> = data.keys().collect();
    sorted_keys.sort();
    let mut result = String::new();
    for key in sorted_keys {
        let value = &data[key];
        if let Some(number) = value.as_i64() {
            result.push_str(&(number * 10000).to_string());
        } else if let Some(object) = value.as_object() {
            result.push_str(&get_tn(object));
        } else {
            result.push_str(value.as_str().unwrap_or(""));
        }
    }
    return result;
}

fn aes_encrypt(data: &[u8], key: &[u8]) -> String {
    let encoded_base64 = general_purpose::STANDARD.encode(data);
    let ascii_data = &encoded_base64.into_bytes(); // Convert to ASCII Bytes Vector !important
    let cipher = Cipher::aes_128_cbc();
    // Manually pad to a multiple of 16 bytes
    let mut padded_data = ascii_data.to_vec();
    while padded_data.len() % 16 != 0 {
        padded_data.push(0);
    }
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(b"0102030405060708")).unwrap();
    crypter.pad(true);
    let mut ciphertext = vec![0; padded_data.len() + cipher.block_size()];
    let count = crypter.update(&padded_data, &mut ciphertext).unwrap();
    let final_count = crypter.finalize(&mut ciphertext[count..]).unwrap();
    ciphertext.truncate(count + final_count);
    hex::encode(ciphertext)
}

fn get_smid() -> String {
    let time_str = Local::now().format("%Y%m%d%H%M%S").to_string();
    let uid = Uuid::new_v4().to_string();
    let mut hasher = Md5::new();
    hasher.update(uid.as_bytes());
    let v = format!("{}{:x}00", time_str, hasher.finalize());
    let mut hasher = Md5::new();
    hasher.update(format!("smsk_web_{}", v).as_bytes());
    let smsk_web = hasher.finalize();
    let mut result = String::from(v);
    for byte in &smsk_web[0..7] {
        result.push_str(&format!("{:02x}", byte));
    }
    result.push('0');
    return result;
}

pub fn generate_signature(token: &str, path: &str, body_or_query: &str) -> (String, HashMap<String, Value>) {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let header_ca: HashMap<String, Value> = serde_json::from_value(json!({"platform": "", "timestamp": timestamp, "dId": "", "vName": ""})).unwrap();
    let header_ca_str = format!(r#"{{"platform":"","timestamp":"{}","dId":"","vName":""}}"#, timestamp);
    let s = format!("{}{}{}{}", path, body_or_query, timestamp, header_ca_str);
    let mut mac = Hmac::<Sha256>::new_from_slice(token.as_bytes()).unwrap();
    mac.update(s.as_bytes());
    let hex_s = hex::encode(mac.finalize().into_bytes());
    let mut hasher = Md5::new();
    hasher.update(hex_s.as_bytes());
    let md5_hex = format!("{:x}", hasher.finalize());
    return (md5_hex, header_ca);
}
