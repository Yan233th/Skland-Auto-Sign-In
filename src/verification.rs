use base64::{engine::general_purpose, Engine};
use md5::{Digest, Md5};
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
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
    "protocol": "102",
    "organization": "UWXspnCCJN4sfYlNfqps",
    "appId": "default",
    "os": "web",
    "version": "3.0.0",
    "sdkver": "3.0.0",
    "box": "",
    "rtype": "all",
    "subVersion": "1.0.0",
    "time": "0"
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

pub fn get_d_id() -> String {
    let uid = Uuid::new_v4().to_string().as_bytes().to_vec();
    let mut hasher = Md5::new();
    hasher.update(uid.as_slice());
    let primary_id = &hex::encode(hasher.finalize())[0..16];
    let encrypted_ep = rsa_encrypt(
        uid.as_slice(),
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmxMNr7n8ZeT0tE1R9j/mPixoinPkeM+k4VGIn/s0k7N5rJAfnZ0eMER+QhwFvshzo0LNmeUkpR8uIlU/GEVr8mN28sKmwd2gpygqj0ePnBmOW4v0ZVwbSYK+izkhVFk2V/doLoMbWy6b+UnA8mkjvg0iYWRByfRsK2gdl7llqCwIDAQAB",
    );
    let base64_ep = general_purpose::STANDARD.encode(encrypted_ep);
    let browser_env_map: HashMap<String, String> = serde_json::from_str(BROWSER_ENV).expect("Failed to parse BROWSER_ENV");
    let mut browser_data = browser_env_map.clone();
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_millis();
    browser_data.insert("vpw".to_string(), Uuid::new_v4().to_string());
    browser_data.insert("svm".to_string(), current_time.to_string());
    browser_data.insert("trees".to_string(), Uuid::new_v4().to_string());
    browser_data.insert("pmf".to_string(), current_time.to_string());
    let mut des_target: HashMap<String, String> = serde_json::from_str(DES_TARGET).expect("Failed to parse DES_TARGET");
    des_target.extend(browser_data);
    des_target.insert("smid".to_string(), generate_smid());
    let tn = generate_tn(&des_target);
    let mut hasher = Md5::new();
    hasher.update(tn.as_bytes());
    des_target.insert("tn".to_string(), hex::encode(hasher.finalize()));
    let gzip_result = gzip_compress(&des_encrypt(&des_target));
    let aes_result = aes_encrypt(&gzip_result, primary_id.as_bytes());
    let client = Client::new();
    let response = client
        .post("https://fp-it.portal101.cn/deviceprofile/v4")
        .json(&serde_json::json!({
            "appId": "default",
            "compress": 2,
            "data": aes_result,
            "encode": 5,
            "ep": base64_ep,
            "organization": "UWXspnCCJN4sfYlNfqps",
            "os": "web"
        }))
        .send()
        .expect("request error");
    let resp: Value = response.json().expect("response json error");
    if resp["code"] != 1100 {
        panic!("did 计算失败，请联系作者");
    }
    let device_id = resp["detail"].get("deviceId").and_then(Value::as_str).expect("deviceId is null");
    return "B".to_string() + device_id;
}

fn des_encrypt(data: &HashMap<String, String>) -> HashMap<String, String> {
    let des_rule_map: HashMap<String, Value> = serde_json::from_str(DES_RULE).expect("Failed to parse DES_RULE");
    let mut result = HashMap::new();
    for (key, value) in data.iter() {
        if let Some(rule) = des_rule_map.get(key) {
            if let Some(obfuscated_name) = rule.get("obfuscated_name").and_then(Value::as_str) {
                if rule.get("is_encrypt").and_then(Value::as_i64) == Some(1) {
                    if let Some(des_key_str) = rule.get("key").and_then(Value::as_str) {
                        let des_key = Key::from_slice(des_key_str.as_bytes()).unwrap();
                        let mut data_bytes = value.as_bytes().to_vec();
                        data_bytes.extend(std::iter::repeat(0u8).take(8));
                        let data_block: Block = data_bytes.as_slice().try_into().unwrap();
                        let cipher = TripleDes::new(des_key);
                        let mut encrypted_block = Block::default();
                        cipher.encrypt_block(&mut encrypted_block, &data_block);
                        result.insert(obfuscated_name.to_string(), general_purpose::STANDARD.encode(encrypted_block.as_slice()));
                    }
                } else {
                    result.insert(obfuscated_name.to_string(), value.to_string());
                }
            }
        } else {
            result.insert(key.to_string(), value.to_string());
        }
    }
    result
}

fn aes_encrypt(data: &[u8], key: &[u8]) -> String {
    let iv = b"0102030405060708";
    let aes_key = aes::Key::from_slice(key).expect("aes key error");
    let cipher = Cbc::<Aes128, Pkcs7>::new(aes_key, iv.into());
    let mut buffer = data.to_vec();
    buffer.push(0);
    let padding_len = 16 - (buffer.len() % 16);
    buffer.extend(std::iter::repeat(0u8).take(padding_len));
    let result = cipher.encrypt(buffer.as_slice()).expect("aes encrypt error");
    hex::encode(result)
}

fn gzip_compress(data: &HashMap<String, String>) -> Vec<u8> {
    let json_string = serde_json::to_string(data).expect("json stringify error");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(2));
    encoder.write_all(json_string.as_bytes()).expect("gzip compress error");
    let compressed_bytes = encoder.finish().expect("gzip compress error");
    general_purpose::STANDARD.encode(compressed_bytes).as_bytes().to_vec()
}

fn generate_tn(data: &HashMap<String, String>) -> String {
    let mut sorted_keys: Vec<_> = data.keys().collect();
    sorted_keys.sort();

    let mut result_list = Vec::new();

    for key in sorted_keys {
        let value = data.get(key).unwrap();
        if let Ok(num) = value.parse::<f64>() {
            result_list.push(format!("{}", num * 10000.0))
        } else {
            result_list.push(value.to_string())
        }
    }
    result_list.join("")
}

fn generate_smid() -> String {
    let now = SystemTime::now();
    let since_epoch = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
    let t = time::OffsetDateTime::from(now);
    let time_string = format!("{}{:0>2}{:0>2}{:0>2}{:0>2}{:0>2}", t.year(), t.month() as u8, t.day(), t.hour(), t.minute(), t.second());
    let uuid_str = Uuid::new_v4().to_string();
    let mut hasher = Md5::new();
    hasher.update(uuid_str.as_bytes());
    let v = format!("{}{}{}", time_string, hex::encode(hasher.finalize()), "00");
    let mut hasher = Md5::new();
    hasher.update(("smsk_web_".to_owned() + &v).as_bytes());
    let smsk_web = &hex::encode(hasher.finalize())[0..14];
    format!("{}{}{}", v, smsk_web, "0")
}

fn rsa_encrypt(data: &[u8], public_key: &str) -> Vec<u8> {
    let public_key_decoded = general_purpose::STANDARD.decode(public_key).expect("base64 decode error");
    let pk = PKey::public_key_from_der(&public_key_decoded).expect("rsa pubkey parse error");
    let mut rsa = Rsa::from_public_key(pk).expect("rsa from pubkey error");
    rsa.public_encrypt(data, openssl::rsa::Padding::PKCS1_PADDING).expect("rsa encrypt error")
}
