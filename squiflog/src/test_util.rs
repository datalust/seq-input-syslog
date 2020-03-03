use chrono::{DateTime, Utc};

pub fn to_timestamp(iso8601: &str) -> Option<DateTime<Utc>> {
    Some(DateTime::parse_from_rfc3339(iso8601).expect("invalid test timestamp").with_timezone(&Utc))
}
