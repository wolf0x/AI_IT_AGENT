//! Browser history readers for Chrome, Edge, and Firefox.
//!
//! All three store history in plain SQLite databases — no passwords needed.
//! Files are copied to temp before opening (browser locks the originals).

use serde::Serialize;

use super::webkit_to_iso;

#[derive(Debug, Serialize)]
pub struct HistoryEntry {
    pub browser: String,
    pub profile: String,
    pub url: String,
    pub title: String,
    pub visit_count: i64,
    pub last_visit: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DownloadEntry {
    pub browser: String,
    pub profile: String,
    pub target_path: String,
    pub url: String,
    pub total_bytes: i64,
    pub start_time: Option<String>,
}

/// Read browser history from Chrome, Edge, and Firefox.
pub fn read_all_history(days: u32, limit: usize) -> Vec<HistoryEntry> {
    let mut entries = Vec::new();
    entries.extend(read_chromium_history("Chrome", &chrome_history_paths(), days, limit));
    entries.extend(read_chromium_history("Edge", &edge_history_paths(), days, limit));
    entries.extend(read_firefox_history(days, limit));
    // Sort by last visit descending
    entries.sort_by(|a, b| b.last_visit.cmp(&a.last_visit));
    entries.truncate(limit);
    entries
}

/// Read downloads from Chrome and Edge.
pub fn read_all_downloads(days: u32, limit: usize) -> Vec<DownloadEntry> {
    let mut entries = Vec::new();
    entries.extend(read_chromium_downloads("Chrome", &chrome_history_paths(), days, limit));
    entries.extend(read_chromium_downloads("Edge", &edge_history_paths(), days, limit));
    entries.sort_by(|a, b| b.start_time.cmp(&a.start_time));
    entries.truncate(limit);
    entries
}

fn chrome_history_paths() -> Vec<String> {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let user_data = format!(r"{}\Google\Chrome\User Data", base);
    find_profiles(&user_data)
}

fn edge_history_paths() -> Vec<String> {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let user_data = format!(r"{}\Microsoft\Edge\User Data", base);
    find_profiles(&user_data)
}

fn find_profiles(user_data_dir: &str) -> Vec<String> {
    let path = std::path::Path::new(user_data_dir);
    if !path.exists() {
        return Vec::new();
    }
    let mut profiles = Vec::new();
    if let Ok(rd) = std::fs::read_dir(path) {
        for entry in rd.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "Default" || name.starts_with("Profile ") {
                let history = entry.path().join("History");
                if history.exists() {
                    profiles.push(history.to_string_lossy().to_string());
                }
            }
        }
    }
    profiles
}

/// Read Chromium (Chrome/Edge) history from the given History file paths.
fn read_chromium_history(
    browser: &str,
    paths: &[String],
    days: u32,
    limit: usize,
) -> Vec<HistoryEntry> {
    let mut entries = Vec::new();
    for path in paths {
        let profile = extract_profile_name(path);
        if let Some(mut e) = read_chromium_db(browser, &profile, path, days, limit) {
            entries.append(&mut e);
        }
    }
    entries
}

fn read_chromium_db(
    browser: &str,
    profile: &str,
    history_path: &str,
    days: u32,
    limit: usize,
) -> Option<Vec<HistoryEntry>> {
    // Copy to temp to avoid file lock
    let temp = copy_to_temp(history_path)?;
    // Also copy WAL if exists
    let wal_path = format!("{}-wal", history_path);
    let temp_wal = format!("{}-wal", &temp);
    let _ = std::fs::copy(&wal_path, &temp_wal);

    let conn = rusqlite::Connection::open_with_flags(
        &temp,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;

    // WebKit timestamp for cutoff
    let cutoff_webkit = webkit_cutoff(days);

    let mut stmt = conn
        .prepare(
            "SELECT url, title, visit_count, last_visit_time FROM urls \
             WHERE last_visit_time >= ?1 ORDER BY last_visit_time DESC LIMIT ?2",
        )
        .ok()?;

    let rows = stmt
        .query_map(rusqlite::params![cutoff_webkit, limit as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .ok()?;

    let mut entries = Vec::new();
    for row in rows.flatten() {
        let last_visit = webkit_to_iso(row.3 as u64);
        entries.push(HistoryEntry {
            browser: browser.to_string(),
            profile: profile.to_string(),
            url: row.0,
            title: row.1,
            visit_count: row.2,
            last_visit,
        });
    }
    // Cleanup temp
    let _ = std::fs::remove_file(&temp);
    let _ = std::fs::remove_file(&temp_wal);
    Some(entries)
}

fn read_chromium_downloads(
    browser: &str,
    paths: &[String],
    days: u32,
    limit: usize,
) -> Vec<DownloadEntry> {
    let mut entries = Vec::new();
    for path in paths {
        let profile = extract_profile_name(path);
        let temp = match copy_to_temp(path) {
            Some(t) => t,
            None => continue,
        };
        let wal = format!("{}-wal", path);
        let temp_wal = format!("{}-wal", &temp);
        let _ = std::fs::copy(&wal, &temp_wal);

        if let Ok(conn) = rusqlite::Connection::open_with_flags(
            &temp,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            let cutoff = webkit_cutoff(days);
            if let Ok(mut stmt) = conn.prepare(
                "SELECT target_path, tab_url, total_bytes, start_time FROM downloads \
                 WHERE start_time >= ?1 ORDER BY start_time DESC LIMIT ?2",
            ) {
                if let Ok(rows) = stmt.query_map(rusqlite::params![cutoff, limit as i64], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                }) {
                    for row in rows.flatten() {
                        entries.push(DownloadEntry {
                            browser: browser.to_string(),
                            profile: profile.to_string(),
                            target_path: row.0,
                            url: row.1,
                            total_bytes: row.2,
                            start_time: webkit_to_iso(row.3 as u64),
                        });
                    }
                }
            }
        }
        let _ = std::fs::remove_file(&temp);
        let _ = std::fs::remove_file(&temp_wal);
    }
    entries
}

/// Read Firefox history from places.sqlite.
fn read_firefox_history(days: u32, limit: usize) -> Vec<HistoryEntry> {
    let mut entries = Vec::new();
    let profiles_dir = format!(
        r"{}\Mozilla\Firefox\Profiles",
        std::env::var("APPDATA").unwrap_or_default()
    );
    let path = std::path::Path::new(&profiles_dir);
    if !path.exists() {
        return entries;
    }
    if let Ok(rd) = std::fs::read_dir(path) {
        for profile_dir in rd.filter_map(|e| e.ok()) {
            let places = profile_dir.path().join("places.sqlite");
            if !places.exists() {
                continue;
            }
            let places_str = places.to_string_lossy().to_string();
            let profile_name = profile_dir.file_name().to_string_lossy().to_string();
            let temp = match copy_to_temp(&places_str) {
                Some(t) => t,
                None => continue,
            };
            // Copy WAL/SHM
            let _ = std::fs::copy(format!("{}-wal", places_str), format!("{}-wal", &temp));
            let _ = std::fs::copy(format!("{}-shm", places_str), format!("{}-shm", &temp));

            if let Ok(conn) = rusqlite::Connection::open_with_flags(
                &temp,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            ) {
                // Firefox timestamps: microseconds since Unix epoch
                let cutoff_unix = unix_cutoff(days);
                let cutoff_us = cutoff_unix * 1_000_000;
                if let Ok(mut stmt) = conn.prepare(
                    "SELECT url, title, visit_count, last_visit_date FROM moz_places \
                     WHERE last_visit_date >= ?1 ORDER BY last_visit_date DESC LIMIT ?2",
                ) {
                    if let Ok(rows) =
                        stmt.query_map(rusqlite::params![cutoff_us, limit as i64], |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, i64>(2)?,
                                row.get::<_, i64>(3)?,
                            ))
                        })
                    {
                        for row in rows.flatten() {
                            let last_visit = super::unix_to_iso(row.3 / 1_000_000);
                            entries.push(HistoryEntry {
                                browser: "Firefox".to_string(),
                                profile: profile_name.clone(),
                                url: row.0,
                                title: row.1,
                                visit_count: row.2,
                                last_visit,
                            });
                        }
                    }
                }
            }
            let _ = std::fs::remove_file(&temp);
            let _ = std::fs::remove_file(format!("{}-wal", &temp));
            let _ = std::fs::remove_file(format!("{}-shm", &temp));
        }
    }
    entries
}

// ─── Helpers ───

fn extract_profile_name(path: &str) -> String {
    std::path::Path::new(path)
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "Unknown".into())
}

fn copy_to_temp(src: &str) -> Option<String> {
    let temp_dir = std::env::temp_dir();
    let name = format!("ra_hist_{}.db", uuid::Uuid::new_v4());
    let dest = temp_dir.join(&name);
    std::fs::copy(src, &dest).ok()?;
    Some(dest.to_string_lossy().to_string())
}

/// WebKit timestamp cutoff for N days ago.
fn webkit_cutoff(days: u32) -> i64 {
    let now = chrono::Utc::now().timestamp();
    let cutoff = now - (days as i64) * 86400;
    // Convert Unix seconds to WebKit µs
    (cutoff + 11_644_473_600) * 1_000_000
}

/// Unix timestamp cutoff for N days ago (seconds).
fn unix_cutoff(days: u32) -> i64 {
    chrono::Utc::now().timestamp() - (days as i64) * 86400
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webkit_cutoff() {
        let c = webkit_cutoff(0);
        assert!(c > 0);
    }

    #[test]
    fn test_extract_profile() {
        assert_eq!(
            extract_profile_name(r"C:\Users\test\AppData\Local\Google\Chrome\User Data\Default\History"),
            "Default"
        );
    }
}
