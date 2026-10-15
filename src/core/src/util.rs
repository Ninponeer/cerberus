//! Utility functions

use crate::error::Result;
use chrono::{DateTime, Utc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Get current timestamp in nanoseconds since epoch
pub fn now_ns() -> i64 {
    Utc::now().timestamp_nanos_opt().unwrap_or(0)
}

/// Get current timestamp in milliseconds since epoch
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Get current timestamp as DateTime<Utc>
pub fn now_utc() -> DateTime<Utc> {
    Utc::now()
}

/// Parse duration from human-readable string (e.g., "5m", "1h", "30s")
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return Err(crate::error::CerberusError::Validation("Empty duration".into()));
    }

    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: u64 = num_str.parse()
        .map_err(|_| crate::error::CerberusError::Validation(format!("Invalid duration number: {}", num_str)))?;

    match unit {
        "s" => Ok(Duration::from_secs(num)),
        "m" => Ok(Duration::from_secs(num * 60)),
        "h" => Ok(Duration::from_secs(num * 3600)),
        "d" => Ok(Duration::from_secs(num * 86400)),
        _ => Err(crate::error::CerberusError::Validation(format!("Invalid duration unit: {}", unit))),
    }
}

/// Format duration as human-readable string
pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

/// Generate a short unique ID (first 8 chars of UUID v7)
pub fn short_id() -> String {
    uuid::Uuid::now_v7().to_string()[..8].to_string()
}

/// Calculate exponential backoff duration
pub fn exponential_backoff(attempt: u32, base: Duration, max: Duration) -> Duration {
    let delay = base * 2_u32.pow(attempt.min(10));
    if delay > max { max } else { delay }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("2d").unwrap(), Duration::from_secs(172800));
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_secs(300)), "5m");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h");
        assert_eq!(format_duration(Duration::from_secs(172800)), "2d");
    }
}