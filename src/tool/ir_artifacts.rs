//! Deep Windows artifact parser tool.
//!
//! Extracts execution evidence from: Prefetch, Amcache, ShimCache,
//! LNK files, UserAssist, and browser history.
//!
//! This tool is the authoritative source for Windows execution artifacts.
//! Use this instead of ir_file for prefetch analysis.

use async_trait::async_trait;
use serde_json::{json, Value};

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;
use crate::forensics;

pub struct IrArtifactsTool;

#[async_trait]
impl Tool for IrArtifactsTool {
    fn name(&self) -> &str {
        "ir_artifacts"
    }
    fn description(&self) -> &str {
        "Deep Windows artifact parser for execution evidence: Prefetch (run count, \
         timestamps, loaded modules), Amcache (SHA1 + path), ShimCache (AppCompatCache), \
         LNK files (target/args), UserAssist (ROT13-decoded execution counts), \
         browser history (Chrome/Edge/Firefox). \
         Use this for execution timeline evidence — NOT ir_file. \
         Requires admin for system artifacts (Prefetch, Amcache, ShimCache)."
    }
    fn is_builtin(&self) -> bool {
        true
    }
    fn is_read_only(&self) -> bool {
        true
    }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": ["all", "prefetch", "amcache", "shimcache", "lnk", "userassist", "browser"],
                    "description": "Which artifact to parse. 'all' runs every parser and tolerates individual failures."
                },
                "limit": {
                    "type": "integer",
                    "description": "Max entries per artifact (default 100)"
                },
                "days": {
                    "type": "integer",
                    "description": "Browser history: only entries from last N days (default 7)"
                },
                "path": {
                    "type": "string",
                    "description": "Custom path: prefetch directory, LNK file/directory, or Amcache.hve path"
                }
            },
            "required": ["mode"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let mode = args["mode"].as_str().unwrap_or("all");
        let limit = args["limit"].as_u64().unwrap_or(100) as usize;
        let days = args["days"].as_u64().unwrap_or(7) as u32;
        let custom_path = args["path"].as_str().map(String::from);

        match mode {
            "all" => Ok(self.run_all(limit, days, custom_path.as_deref()).await),
            "prefetch" => Ok(self.run_prefetch(limit, custom_path.as_deref())),
            "amcache" => Ok(self.run_amcache(limit, custom_path.as_deref())),
            "shimcache" => Ok(self.run_shimcache(limit)),
            "lnk" => Ok(self.run_lnk(limit, custom_path.as_deref())),
            "userassist" => Ok(self.run_userassist(limit)),
            "browser" => Ok(self.run_browser(days, limit)),
            _ => Ok(json!({
                "status": "error",
                "message": format!("Unknown mode '{}'. Valid: all, prefetch, amcache, shimcache, lnk, userassist, browser", mode)
            })),
        }
    }
}

impl IrArtifactsTool {
    async fn run_all(&self, limit: usize, days: u32, custom_path: Option<&str>) -> Value {
        let mut results = serde_json::Map::new();

        // Run all parsers concurrently where possible
        let prefetch = tokio::task::spawn_blocking({
            let p = custom_path.map(String::from);
            move || Self::parse_prefetch(limit, p.as_deref())
        })
        .await;

        let amcache = tokio::task::spawn_blocking({
            let p = custom_path.map(String::from);
            move || Self::parse_amcache(limit, p.as_deref())
        })
        .await;

        let shimcache = tokio::task::spawn_blocking(move || Self::parse_shimcache(limit)).await;

        let lnk = tokio::task::spawn_blocking({
            let p = custom_path.map(String::from);
            move || Self::parse_lnk(limit, p.as_deref())
        })
        .await;

        let userassist = tokio::task::spawn_blocking(move || Self::parse_userassist(limit)).await;

        let browser = tokio::task::spawn_blocking(move || Self::parse_browser(days, limit)).await;

        // Collect results, tolerating individual failures
        if let Ok(Ok(v)) = prefetch {
            results.insert("prefetch".into(), v);
        }
        if let Ok(Ok(v)) = amcache {
            results.insert("amcache".into(), v);
        }
        if let Ok(Ok(v)) = shimcache {
            results.insert("shimcache".into(), v);
        }
        if let Ok(Ok(v)) = lnk {
            results.insert("lnk".into(), v);
        }
        if let Ok(Ok(v)) = userassist {
            results.insert("userassist".into(), v);
        }
        if let Ok(v) = browser {
            results.insert("browser".into(), v);
        }

        json!({
            "status": "ok",
            "mode": "all",
            "artifacts": results,
            "parsers_succeeded": results.len()
        })
    }

    fn run_prefetch(&self, limit: usize, custom_path: Option<&str>) -> Value {
        match Self::parse_prefetch(limit, custom_path) {
            Ok(v) => v,
            Err(e) => json!({"status": "error", "message": e}),
        }
    }

    fn run_amcache(&self, limit: usize, custom_path: Option<&str>) -> Value {
        match Self::parse_amcache(limit, custom_path) {
            Ok(v) => v,
            Err(e) => json!({"status": "error", "message": e}),
        }
    }

    fn run_shimcache(&self, limit: usize) -> Value {
        match Self::parse_shimcache(limit) {
            Ok(v) => v,
            Err(e) => json!({"status": "error", "message": e}),
        }
    }

    fn run_lnk(&self, limit: usize, custom_path: Option<&str>) -> Value {
        match Self::parse_lnk(limit, custom_path) {
            Ok(v) => v,
            Err(e) => json!({"status": "error", "message": e}),
        }
    }

    fn run_userassist(&self, limit: usize) -> Value {
        match Self::parse_userassist(limit) {
            Ok(v) => v,
            Err(e) => json!({"status": "error", "message": e}),
        }
    }

    fn run_browser(&self, days: u32, limit: usize) -> Value {
        Self::parse_browser(days, limit)
    }

    // ─── Parser implementations ───

    fn parse_prefetch(limit: usize, custom_path: Option<&str>) -> Result<Value, String> {
        let dir = custom_path.unwrap_or(r"C:\Windows\Prefetch");
        let entries = forensics::prefetch::parse_prefetch_dir(dir, limit)?;
        let count = entries.len();
        Ok(json!({
            "status": "ok",
            "mode": "prefetch",
            "directory": dir,
            "count": count,
            "entries": entries
        }))
    }

    fn parse_amcache(limit: usize, custom_path: Option<&str>) -> Result<Value, String> {
        let default_path = r"C:\Windows\AppCompat\Programs\Amcache.hve";
        let path = custom_path.unwrap_or(default_path);
        
        // Copy to temp to avoid file lock (Amcache.hve is locked by the system)
        let tmp_path = std::env::temp_dir().join("Amcache_rustagent.hve");
        let hive = if custom_path.is_none() {
            std::fs::copy(path, &tmp_path)
                .map_err(|e| format!("Cannot copy Amcache.hve (admin required?): {}", e))?;
            let result = forensics::hive::HiveFile::open(tmp_path.to_str().unwrap());
            let _ = std::fs::remove_file(&tmp_path);
            result?
        } else {
            forensics::hive::HiveFile::open(path)?
        };

        let mut results = Vec::new();
        // Enumerate Root\File\{VolumeGUID}\{FileRef}
        if let Some(file_key) = hive.find_key("File") {
            let volumes = hive.enum_subkeys(file_key);
            for vol in &volumes {
                if let Some(vol_off) = hive.find_subkey(file_key, vol) {
                    let files = hive.enum_subkeys(vol_off);
                    for file_ref in &files {
                        if results.len() >= limit {
                            break;
                        }
                        if let Some(file_off) = hive.find_subkey(vol_off, file_ref) {
                            let values = hive.enum_values(file_off);
                            let mut entry = serde_json::Map::new();
                            for v in &values {
                                match v.name.as_str() {
                                    "15" | "16" => {
                                        entry.insert(
                                            "path".into(),
                                            json!(forensics::hive::value_to_string(v)),
                                        );
                                    }
                                    "17" | "101" => {
                                        let sha1 = forensics::hive::value_to_string(v);
                                        // Strip "0000" prefix if present
                                        let sha1 = if sha1.starts_with("0000") {
                                            sha1[4..].to_string()
                                        } else {
                                            sha1
                                        };
                                        entry.insert("sha1".into(), json!(sha1));
                                    }
                                    "12" => {
                                        if let Some(ts) = forensics::hive::value_to_dword(v) {
                                            entry.insert(
                                                "compile_time".into(),
                                                json!(forensics::unix_to_iso(ts as i64)),
                                            );
                                        }
                                    }
                                    "5" => {
                                        if let Some(sz) = forensics::hive::value_to_dword(v) {
                                            entry.insert("file_size".into(), json!(sz));
                                        }
                                    }
                                    "0" => {
                                        entry.insert(
                                            "product_name".into(),
                                            json!(forensics::hive::value_to_string(v)),
                                        );
                                    }
                                    "1" => {
                                        entry.insert(
                                            "company".into(),
                                            json!(forensics::hive::value_to_string(v)),
                                        );
                                    }
                                    _ => {}
                                }
                            }
                            if entry.contains_key("path") {
                                results.push(Value::Object(entry));
                            }
                        }
                    }
                }
                if results.len() >= limit {
                    break;
                }
            }
        }
        Ok(json!({
            "status": "ok",
            "mode": "amcache",
            "hive": path,
            "count": results.len(),
            "entries": results
        }))
    }

    fn parse_shimcache(limit: usize) -> Result<Value, String> {
        let data = forensics::regapi::read_binary_value(
            "HKLM",
            r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache",
            "AppCompatCache",
        )
        .ok_or_else(|| "Cannot read ShimCache from registry (admin required)".to_string())?;

        let mut entries = forensics::shimcache::parse_shimcache(&data)?;
        entries.truncate(limit);
        let count = entries.len();
        Ok(json!({
            "status": "ok",
            "mode": "shimcache",
            "count": count,
            "entries": entries
        }))
    }

    fn parse_lnk(limit: usize, custom_path: Option<&str>) -> Result<Value, String> {
        let default_dir = match custom_path {
            Some(p) if !p.is_empty() => p.to_string(),
            _ => {
                let appdata = std::env::var("APPDATA").unwrap_or_default();
                format!(r"{}\Microsoft\Windows\Recent", appdata)
            }
        };

        // Check if path is a single file or directory
        let p = std::path::Path::new(&default_dir);
        if p.is_file() {
            let data = std::fs::read(p).map_err(|e| format!("Cannot read '{}': {}", default_dir, e))?;
            let entry = forensics::lnk::parse_lnk(&data)
                .ok_or_else(|| "Not a valid LNK file".to_string())?;
            return Ok(json!({
                "status": "ok",
                "mode": "lnk",
                "count": 1,
                "entries": [entry]
            }));
        }

        let entries = forensics::lnk::parse_lnk_dir(&default_dir, limit)?;
        let count = entries.len();
        Ok(json!({
            "status": "ok",
            "mode": "lnk",
            "directory": default_dir,
            "count": count,
            "entries": entries
        }))
    }

    fn parse_userassist(limit: usize) -> Result<Value, String> {
        let mut entries = forensics::userassist::read_userassist()?;
        entries.truncate(limit);
        let count = entries.len();
        Ok(json!({
            "status": "ok",
            "mode": "userassist",
            "count": count,
            "entries": entries
        }))
    }

    fn parse_browser(days: u32, limit: usize) -> Value {
        let history = forensics::browser::read_all_history(days, limit);
        let downloads = forensics::browser::read_all_downloads(days, limit);
        json!({
            "status": "ok",
            "mode": "browser",
            "days": days,
            "history_count": history.len(),
            "downloads_count": downloads.len(),
            "history": history,
            "downloads": downloads
        })
    }
}
