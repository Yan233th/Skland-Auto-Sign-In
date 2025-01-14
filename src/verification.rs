use std::{time::{SystemTime, UNIX_EPOCH}, collections::HashMap};
use reqwest::blocking::Client;
use base64::{engine::general_purpose, Engine};
use md5::{Md5, Digest};
use serde_json::{json, Value};
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
    des_target.insert("tn".to_string(), hasher.result_str());
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
