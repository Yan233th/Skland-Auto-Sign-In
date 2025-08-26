use once_cell::sync::Lazy;
use reqwest::Error;
use std::{env, thread::sleep, time::Duration};

pub static MAX_RETRIES: Lazy<usize> = Lazy::new(|| env::var("MAX_RETRIES").ok().and_then(|s| s.parse().ok()).unwrap_or(3));

pub fn retry_request<T>(mut f: impl FnMut() -> Result<T, Error>) -> T {
    for attempt in 1..=*MAX_RETRIES {
        match f() {
            Ok(val) => return val,
            Err(e) => {
                eprintln!("Attempt {attempt} failed: {e}");
                sleep(Duration::from_secs(1));
            }
        }
    }
    panic!("Failed after {} attempts", *MAX_RETRIES)
}
