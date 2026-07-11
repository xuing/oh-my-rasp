//! Small shared helpers.

use std::path::Path;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Current UTC time as an RFC3339 string (e.g. `2026-06-06T12:00:00.123456Z`).
pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

/// Restrict a file to owner read/write only (mode `0600`).
///
/// The daemon writes several files under `/tmp` that carry sensitive data — the
/// control file holds the cloud policy and the outbox holds raw attack request
/// context. Under the default umask these land world-readable (`0644`); tightening
/// them to `0600` keeps other local users from reading them. Unix-only; a no-op on
/// other platforms.
#[cfg(unix)]
pub fn restrict_to_owner(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
pub fn restrict_to_owner(_path: &Path) -> std::io::Result<()> {
    Ok(())
}
