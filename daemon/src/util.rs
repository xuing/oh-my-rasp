//! Small shared helpers.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Current UTC time as an RFC3339 string (e.g. `2026-06-06T12:00:00.123456Z`).
pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}
