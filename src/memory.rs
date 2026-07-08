//! SQLite-backed conversation memory store.
//!
//! Stores all conversations by date and provides summarization capabilities.
//! On new sessions, recent summaries are injected as context.

use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationEntry {
    pub id: i64,
    pub date: String,
    pub session_id: String,
    pub role: String,
    pub content: String,
    pub tool_name: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryEntry {
    pub id: i64,
    pub date: String,
    pub summary: String,
    pub created_at: String,
}

/// A checkpoint of an in-progress agent task, persisted to SQLite
/// so it can be resumed after a crash or restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskCheckpoint {
    pub id: String,
    pub session_id: String,
    pub model_name: String,
    pub user_message: String,
    /// Full conversation history serialized as JSON array of ChatMessage.
    pub history_json: String,
    /// Iteration number when the checkpoint was saved.
    pub iteration: usize,
    /// Human-readable summary of tools used (e.g. "bash, read_file (3 rounds)").
    pub tool_summary: String,
    pub created_at: String,
    pub updated_at: String,
}

pub struct MemoryStore {
    conn: Mutex<Connection>,
    db_path: PathBuf,
}

fn compose_summary_from_entries(entries: &[ConversationEntry]) -> Result<String, String> {
    if entries.is_empty() {
        return Err("No conversations to summarize".to_string());
    }

    let mut parts: Vec<String> = Vec::new();

    let user_msgs: Vec<String> = entries.iter()
        .filter(|e| e.role == "user")
        .map(|e| e.content.chars().take(150).collect::<String>())
        .collect();
    if !user_msgs.is_empty() {
        parts.push(format!("User questions/topics ({}):", user_msgs.len()));
        for (i, m) in user_msgs.iter().take(30).enumerate() {
            parts.push(format!("  {}. {}", i + 1, m));
        }
    }

    let asst_msgs: Vec<String> = entries.iter()
        .filter(|e| e.role == "assistant")
        .map(|e| e.content.chars().take(200).collect::<String>())
        .collect();
    if !asst_msgs.is_empty() {
        parts.push(format!("\nAssistant responses ({}):", asst_msgs.len()));
        for (i, m) in asst_msgs.iter().take(15).enumerate() {
            parts.push(format!("  {}. {}", i + 1, m));
        }
    }

    if parts.is_empty() {
        return Err("No user/assistant entries to summarize".to_string());
    }

    let mut summary = parts.join("\n");
    if summary.len() > 4000 {
        summary = format!(
            "{}\n\n... [summary truncated]",
            summary.chars().take(4000).collect::<String>()
        );
    }
    Ok(summary)
}

fn is_cjk_char(c: char) -> bool {
    matches!(c,
        '\u{4e00}'..='\u{9fff}'
        | '\u{3400}'..='\u{4dbf}'
        | '\u{f900}'..='\u{faff}'
        | '\u{2e80}'..='\u{2eff}'
        | '\u{3000}'..='\u{303f}'
        | '\u{3040}'..='\u{309f}'
        | '\u{30a0}'..='\u{30ff}'
        | '\u{ac00}'..='\u{d7af}'
    )
}

/// Insert spaces between consecutive CJK characters so that the FTS5
/// `unicode61` tokenizer treats each CJK character as an individual token.
/// Latin words are left untouched (their existing whitespace is preserved).
fn preprocess_for_fts(text: &str) -> String {
    let mut result = String::with_capacity(text.len() + text.len() / 4);
    let mut prev_cjk = false;
    for ch in text.chars() {
        if is_cjk_char(ch) {
            if prev_cjk {
                result.push(' ');
            }
            result.push(ch);
            prev_cjk = true;
        } else {
            if prev_cjk {
                result.push(' ');
            }
            result.push(ch);
            prev_cjk = false;
        }
    }
    result
}

/// Build FTS5 query tokens from a user query string.
///
/// - CJK segments → 2-character phrase queries (e.g. `"安 全"`)
/// - Latin words → quoted exact-match tokens (e.g. `"security"`)
///
/// All tokens are returned ready to be joined with ` OR ` for the FTS5
/// MATCH expression.
fn build_fts_query_tokens(query: &str) -> Vec<String> {
    let mut tokens = Vec::new();

    for word in query.split_whitespace() {
        if word.is_empty() {
            continue;
        }
        let lower = word.to_lowercase();
        let chars: Vec<char> = lower.chars().collect();
        let has_cjk = chars.iter().copied().any(is_cjk_char);

        if has_cjk {
            // Generate CJK bigram phrase queries.
            // Each bigram becomes `"X Y"` which FTS5 matches as adjacent tokens.
            for window in chars.windows(2) {
                let c0 = window[0];
                let c1 = window[1];
                if is_cjk_char(c0) || is_cjk_char(c1) {
                    // Escape any double-quotes inside the token
                    let s = format!("{} {}", c0, c1);
                    tokens.push(format!("\"{}\"", s.replace('"', "\"\"")));
                }
            }
            // Also add the full CJK string as individual character tokens OR'd
            // so that single-char queries still match something.
            if chars.len() == 1 && is_cjk_char(chars[0]) {
                let escaped = format!("{}", chars[0]).replace('"', "\"\"");
                tokens.push(format!("\"{}\"", escaped));
            }
        } else {
            // Latin word — quote it for exact token match
            let escaped = lower.replace('"', "\"\"");
            tokens.push(format!("\"{}\"", escaped));
        }
    }

    // Fallback: if the query had no whitespace (single CJK string),
    // generate bigrams from the whole string.
    if tokens.is_empty() {
        let lower = query.trim().to_lowercase();
        if !lower.is_empty() {
            let chars: Vec<char> = lower.chars().collect();
            if chars.iter().copied().any(is_cjk_char) {
                for window in chars.windows(2) {
                    let c0 = window[0];
                    let c1 = window[1];
                    if is_cjk_char(c0) || is_cjk_char(c1) {
                        let s = format!("{} {}", c0, c1);
                        tokens.push(format!("\"{}\"", s.replace('"', "\"\"")));
                    }
                }
            }
            if tokens.is_empty() {
                let escaped = lower.replace('"', "\"\"");
                tokens.push(format!("\"{}\"", escaped));
            }
        }
    }

    tokens
}

/// Legacy keyword extraction — kept for `is_recall_query()` in server.rs.
/// The FTS5 search path uses `build_fts_query_tokens` instead.
fn extract_search_keywords(query: &str) -> Vec<String> {
    let mut keywords = Vec::new();

    for token in query.split_whitespace() {
        if token.is_empty() {
            continue;
        }
        let lower = token.to_lowercase();
        let chars: Vec<char> = lower.chars().collect();
        let has_cjk = chars.iter().copied().any(is_cjk_char);

        if has_cjk {
            for window in chars.windows(2) {
                let bigram: String = window.iter().collect();
                if bigram.chars().any(is_cjk_char) {
                    keywords.push(bigram);
                }
            }
            keywords.push(lower);
        } else {
            keywords.push(lower);
        }
    }

    if keywords.is_empty() {
        let lower = query.trim().to_lowercase();
        if !lower.is_empty() {
            let chars: Vec<char> = lower.chars().collect();
            if chars.iter().copied().any(is_cjk_char) {
                for window in chars.windows(2) {
                    let bigram: String = window.iter().collect();
                    if bigram.chars().any(is_cjk_char) {
                        keywords.push(bigram);
                    }
                }
            }
            keywords.push(lower);
        }
    }

    keywords.sort();
    keywords.dedup();
    keywords
}

impl MemoryStore {
    /// Open or create the SQLite database at the given path.
    pub fn new(db_path: &str) -> Result<Self, String> {
        let path = PathBuf::from(db_path);
        let conn = Connection::open(&path)
            .map_err(|e| format!("Failed to open memory DB: {}", e))?;

        // Enable WAL mode for better concurrent performance
        conn.execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(|e| format!("Failed to set WAL mode: {}", e))?;

        let store = Self {
            conn: Mutex::new(conn),
            db_path: path,
        };
        store.migrate()?;
        info!("Memory store initialized: {}", db_path);
        Ok(store)
    }

    /// Run schema migrations.
    fn migrate(&self) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                session_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                tool_name TEXT,
                timestamp TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_conv_date ON conversations(date);
            CREATE INDEX IF NOT EXISTS idx_conv_session ON conversations(session_id);

            CREATE TABLE IF NOT EXISTS summaries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL UNIQUE,
                summary TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER NOT NULL
            );"
        ).map_err(|e| format!("Migration failed: {}", e))?;

        // Insert version if not exists
        let version: i64 = conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        ).unwrap_or(0);

        if version < 1 {
            conn.execute("INSERT OR REPLACE INTO schema_version (version) VALUES (1)", [])
                .map_err(|e| format!("Version insert failed: {}", e))?;
        }

        // ── Schema v2: FTS5 full-text search index ──────────────
        if version < 2 {
            // Standalone FTS5 table (not content-synced, because we need
            // CJK preprocessing before indexing — triggers can't call Rust).
            conn.execute_batch(
                "CREATE VIRTUAL TABLE IF NOT EXISTS conversations_fts USING fts5(
                    content,
                    tokenize='unicode61 remove_diacritics 0'
                );"
            ).map_err(|e| format!("FTS5 table creation failed: {}", e))?;

            // Backfill existing conversations into the FTS index.
            let rows: Vec<(i64, String)> = conn.prepare(
                "SELECT rowid, content FROM conversations"
            )
            .map_err(|e| format!("FTS backfill query failed: {}", e))?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| format!("FTS backfill query_map failed: {}", e))?
            .filter_map(|r| r.ok())
            .collect();

            for (rowid, content) in &rows {
                let fts_content = preprocess_for_fts(content);
                conn.execute(
                    "INSERT INTO conversations_fts(rowid, content) VALUES (?1, ?2)",
                    params![rowid, fts_content],
                ).map_err(|e| format!("FTS backfill insert failed: {}", e))?;
            }

            conn.execute("INSERT INTO schema_version(version) VALUES(2)", [])
                .map_err(|e| format!("Version 2 insert failed: {}", e))?;

            info!("Schema v2 migration: FTS5 index created ({} entries indexed)", rows.len());
        }

        // ── Schema v3: Task checkpoints for crash recovery ──────
        if version < 3 {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS task_checkpoints (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    model_name TEXT NOT NULL,
                    user_message TEXT NOT NULL,
                    history_json TEXT NOT NULL,
                    iteration INTEGER NOT NULL DEFAULT 0,
                    tool_summary TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );"
            ).map_err(|e| format!("Checkpoint table creation failed: {}", e))?;

            conn.execute("INSERT INTO schema_version(version) VALUES(3)", [])
                .map_err(|e| format!("Version 3 insert failed: {}", e))?;

            info!("Schema v3 migration: task_checkpoints table created");
        }

        Ok(())
    }

    /// Store a conversation entry and update the FTS5 index.
    pub fn store_entry(
        &self,
        session_id: &str,
        role: &str,
        content: &str,
        tool_name: Option<&str>,
    ) -> Result<i64, String> {
        let date = Utc::now().format("%Y-%m-%d").to_string();
        let timestamp = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO conversations (date, session_id, role, content, tool_name, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![date, session_id, role, content, tool_name, timestamp],
        ).map_err(|e| format!("Failed to store entry: {}", e))?;
        let rowid = conn.last_insert_rowid();

        // Also insert into FTS5 index with CJK-preprocessed content.
        // FTS5 table may not exist on very old DBs that haven't migrated yet;
        // silently ignore that error.
        let fts_content = preprocess_for_fts(content);
        let _ = conn.execute(
            "INSERT INTO conversations_fts(rowid, content) VALUES (?1, ?2)",
            params![rowid, fts_content],
        );

        Ok(rowid)
    }

    /// Get all conversation entries for a specific date.
    pub fn get_entries_by_date(&self, date: &str) -> Result<Vec<ConversationEntry>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, date, session_id, role, content, tool_name, timestamp FROM conversations WHERE date = ?1 ORDER BY timestamp ASC"
        ).map_err(|e| format!("Query prepare failed: {}", e))?;

        let entries = stmt.query_map(params![date], |row| {
            Ok(ConversationEntry {
                id: row.get(0)?,
                date: row.get(1)?,
                session_id: row.get(2)?,
                role: row.get(3)?,
                content: row.get(4)?,
                tool_name: row.get(5)?,
                timestamp: row.get(6)?,
            })
        }).map_err(|e| format!("Query failed: {}", e))?
        .filter_map(|r| r.ok())
        .collect();

        Ok(entries)
    }

    /// Get recent entries from the last N days.
    pub fn get_recent_entries(&self, days: usize) -> Result<Vec<ConversationEntry>, String> {
        let since = (Utc::now() - chrono::Duration::days(days as i64))
            .format("%Y-%m-%d")
            .to_string();
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, date, session_id, role, content, tool_name, timestamp FROM conversations WHERE date >= ?1 ORDER BY timestamp ASC"
        ).map_err(|e| format!("Query prepare failed: {}", e))?;

        let entries = stmt.query_map(params![since], |row| {
            Ok(ConversationEntry {
                id: row.get(0)?,
                date: row.get(1)?,
                session_id: row.get(2)?,
                role: row.get(3)?,
                content: row.get(4)?,
                tool_name: row.get(5)?,
                timestamp: row.get(6)?,
            })
        }).map_err(|e| format!("Query failed: {}", e))?
        .filter_map(|r| r.ok())
        .collect();

        Ok(entries)
    }

    /// Full-text search across recent conversation entries using FTS5.
    ///
    /// Uses BM25 ranking so the most relevant results come first.
    /// CJK text is handled via bigram phrase queries.
    /// Falls back to the legacy linear scan if the FTS5 table is missing.
    pub fn search_entries(&self, query: &str, days: usize) -> Result<Vec<ConversationEntry>, String> {
        let tokens = build_fts_query_tokens(query);
        if tokens.is_empty() {
            return Ok(Vec::new());
        }

        let fts_query = tokens.join(" OR ");
        let since = (Utc::now() - chrono::Duration::days(days as i64))
            .format("%Y-%m-%d")
            .to_string();

        let conn = self.conn.lock().unwrap();

        // Try FTS5 search first.
        let fts_result = (|| -> Result<Vec<ConversationEntry>, String> {
            let mut stmt = conn.prepare(
                "SELECT c.id, c.date, c.session_id, c.role, c.content, c.tool_name, c.timestamp
                 FROM conversations_fts f
                 JOIN conversations c ON c.rowid = f.rowid
                 WHERE conversations_fts MATCH ?1
                   AND c.date >= ?2
                 ORDER BY bm25(conversations_fts)
                 LIMIT 30"
            ).map_err(|e| format!("FTS query prepare failed: {}", e))?;

            let entries = stmt.query_map(params![fts_query, since], |row| {
                Ok(ConversationEntry {
                    id: row.get(0)?,
                    date: row.get(1)?,
                    session_id: row.get(2)?,
                    role: row.get(3)?,
                    content: row.get(4)?,
                    tool_name: row.get(5)?,
                    timestamp: row.get(6)?,
                })
            }).map_err(|e| format!("FTS query failed: {}", e))?
            .filter_map(|r| r.ok())
            .collect();

            Ok(entries)
        })();

        match fts_result {
            Ok(entries) => Ok(entries),
            Err(e) => {
                // FTS5 table might not exist (e.g. migration not yet run).
                // Fall back to legacy linear scan.
                warn!("FTS5 search failed ({}), falling back to linear scan", e);
                self.search_entries_legacy(query, days)
            }
        }
    }

    /// Legacy keyword search (fallback when FTS5 is unavailable).
    fn search_entries_legacy(&self, query: &str, days: usize) -> Result<Vec<ConversationEntry>, String> {
        let keywords = extract_search_keywords(query);
        if keywords.is_empty() {
            return Ok(Vec::new());
        }

        let recent = self.get_recent_entries(days)?;
        let mut matched: Vec<ConversationEntry> = Vec::new();
        for entry in recent {
            let content_lower = entry.content.to_lowercase();
            if keywords.iter().any(|kw| content_lower.contains(kw)) {
                matched.push(entry);
            }
        }
        if matched.len() > 30 {
            let start = matched.len() - 30;
            matched = matched.split_off(start);
        }
        Ok(matched)
    }

    /// Build a recall context for a user query by searching SQLite and
    /// summarizing the matching entries. Used when the user asks about past
    /// conversations mid-session.
    pub fn build_recall_context(&self, query: &str, days: usize) -> Option<String> {
        // Ensure daily summaries exist for an overview.
        self.ensure_recent_summaries(days);

        let mut parts: Vec<String> = Vec::new();

        // 1. Keyword-matched entries from the last N days.
        if let Ok(hits) = self.search_entries(query, days) {
            if !hits.is_empty() {
                parts.push(format!("## Relevant past messages matching \"{}\" ({} hits)", query, hits.len()));
                for e in hits.iter().take(20) {
                    let role_label = match e.role.as_str() {
                        "user" => "User",
                        "assistant" => "Assistant",
                        _ => "System",
                    };
                    let preview: String = e.content.chars().take(300).collect();
                    let suffix = if e.content.chars().count() > 300 { "..." } else { "" };
                    parts.push(format!("[{}] {}: {}{}", e.date, role_label, preview, suffix));
                }
            }
        }

        // 2. Daily summaries for broader context.
        let mut added_summary_section = false;
        if let Ok(summaries) = self.get_recent_summaries(days) {
            if !summaries.is_empty() {
                added_summary_section = true;
                parts.push("\n## Daily conversation summaries".to_string());
                for s in &summaries {
                    parts.push(format!("\n### {}", s.date));
                    parts.push(s.summary.clone());
                }
            }
        }
        if !added_summary_section {
            if let Ok(dates) = self.available_dates() {
                let mut generated = Vec::new();
                for date in dates.into_iter().take(days) {
                    if let Ok(entries) = self.get_entries_by_date(&date) {
                        if let Ok(summary) = compose_summary_from_entries(&entries) {
                            generated.push((date, summary));
                        }
                    }
                }
                if !generated.is_empty() {
                    parts.push("\n## Daily conversation summaries".to_string());
                    for (date, summary) in generated {
                        parts.push(format!("\n### {}", date));
                        parts.push(summary);
                    }
                }
            }
        }

        if parts.is_empty() {
            None
        } else {
            Some(format!(
                "[Memory Recall — the user is asking about earlier conversations. \
                 Below are relevant past messages and daily summaries retrieved from \
                 the local memory store. Use them to answer; do NOT claim you have no \
                 memory of past conversations when this block is present.]\n\n{}",
                parts.join("\n")
            ))
        }
    }

    /// Store a summary for a date (upsert).
    pub fn store_summary(&self, date: &str, summary: &str) -> Result<(), String> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO summaries (date, summary, created_at) VALUES (?1, ?2, ?3)",
            params![date, summary, now],
        ).map_err(|e| format!("Failed to store summary: {}", e))?;
        Ok(())
    }

    /// Get recent summaries (last N days).
    pub fn get_recent_summaries(&self, days: usize) -> Result<Vec<SummaryEntry>, String> {
        let since = (Utc::now() - chrono::Duration::days(days as i64))
            .format("%Y-%m-%d")
            .to_string();
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, date, summary, created_at FROM summaries WHERE date >= ?1 ORDER BY date DESC"
        ).map_err(|e| format!("Query prepare failed: {}", e))?;

        let entries = stmt.query_map(params![since], |row| {
            Ok(SummaryEntry {
                id: row.get(0)?,
                date: row.get(1)?,
                summary: row.get(2)?,
                created_at: row.get(3)?,
            })
        }).map_err(|e| format!("Query failed: {}", e))?
        .filter_map(|r| r.ok())
        .collect();

        Ok(entries)
    }

    /// Get all available dates with conversations.
    pub fn available_dates(&self) -> Result<Vec<String>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT DISTINCT date FROM conversations ORDER BY date DESC"
        ).map_err(|e| format!("Query prepare failed: {}", e))?;

        let dates = stmt.query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| format!("Query failed: {}", e))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(dates)
    }

    /// Get all summaries.
    pub fn get_all_summaries(&self) -> Result<Vec<SummaryEntry>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, date, summary, created_at FROM summaries ORDER BY date DESC"
        ).map_err(|e| format!("Query prepare failed: {}", e))?;

        let entries = stmt.query_map([], |row| {
            Ok(SummaryEntry {
                id: row.get(0)?,
                date: row.get(1)?,
                summary: row.get(2)?,
                created_at: row.get(3)?,
            })
        }).map_err(|e| format!("Query failed: {}", e))?
        .filter_map(|r| r.ok())
        .collect();

        Ok(entries)
    }

    /// Get the summary for a single date (if it exists).
    pub fn get_summary_for_date(&self, date: &str) -> Option<String> {
        let conn = self.conn.lock().unwrap();
        let result: rusqlite::Result<String> = conn.query_row(
            "SELECT summary FROM summaries WHERE date = ?1",
            params![date],
            |row| row.get(0),
        );
        result.ok()
    }

    /// Auto-generate an extractive summary for a date's conversations and
    /// persist it (upsert). Returns the generated summary text.
    ///
    /// This is intentionally extractive (no LLM call) so it is cheap to run
    /// after every chat and keeps the daily summary fresh.
    pub fn auto_summarize_date(&self, date: &str) -> Result<String, String> {
        let entries = self.get_entries_by_date(date)?;
        if entries.is_empty() {
            return Err(format!("No conversations for {}", date));
        }
        let summary = compose_summary_from_entries(&entries)?;

        self.store_summary(date, &summary)?;
        Ok(summary)
    }

    /// Ensure summaries exist for the last N days that have conversations.
    /// Today's summary is always refreshed (to capture the latest entries);
    /// past days are generated once.
    pub fn ensure_recent_summaries(&self, days: usize) {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let dates = match self.available_dates() {
            Ok(d) => d,
            Err(_) => return,
        };
        // `available_dates` returns DESC order, so `take(days)` gives the most
        // recent days that actually have conversations.
        for date in dates.into_iter().take(days) {
            if date == today {
                let _ = self.auto_summarize_date(&date);
            } else if self.get_summary_for_date(&date).is_none() {
                let _ = self.auto_summarize_date(&date);
            }
        }
    }

    /// Build a memory context string from recent daily summaries.
    /// This is injected as context so the agent can recall earlier
    /// conversations when the user asks about past topics.
    pub fn build_context_string(&self, summary_days: usize) -> Option<String> {
        // Lazily ensure summaries exist (and today's is fresh) before reading.
        self.ensure_recent_summaries(summary_days);

        let mut parts = Vec::new();

        // Recent daily summaries (includes today if it has conversations).
        // If the summaries table is empty or stale, fall back to synthesizing
        // summaries directly from raw conversation entries.
        let mut added = false;
        if let Ok(summaries) = self.get_recent_summaries(summary_days) {
            if !summaries.is_empty() {
                added = true;
                parts.push("## Past Conversation Summaries".to_string());
                for s in &summaries {
                    parts.push(format!("\n### {}", s.date));
                    parts.push(s.summary.clone());
                }
            }
        }
        if !added {
            if let Ok(dates) = self.available_dates() {
                let mut generated = Vec::new();
                for date in dates.into_iter().take(summary_days) {
                    if let Ok(entries) = self.get_entries_by_date(&date) {
                        if let Ok(summary) = compose_summary_from_entries(&entries) {
                            generated.push((date, summary));
                        }
                    }
                }
                if !generated.is_empty() {
                    parts.push("## Past Conversation Summaries".to_string());
                    for (date, summary) in generated {
                        parts.push(format!("\n### {}", date));
                        parts.push(summary);
                    }
                }
            }
        }

        if parts.is_empty() {
            None
        } else {
            Some(format!(
                "[Memory Context — summaries of earlier conversations with this assistant. \
                 Reference this when the user asks about previous topics, what was discussed \
                 before, or anything from earlier sessions. Do NOT claim you have no memory \
                 when this block is present.]\n\n{}",
                parts.join("\n")
            ))
        }
    }

    /// Generate a summary for a specific date's conversations.
    /// Returns the summary text.
    pub fn build_raw_context_for_date(&self, date: &str) -> Result<String, String> {
        let entries = self.get_entries_by_date(date)?;
        if entries.is_empty() {
            return Err(format!("No conversations found for {}", date));
        }

        let mut parts = Vec::new();
        for entry in &entries {
            let role_label = match entry.role.as_str() {
                "user" => "User",
                "assistant" => "Assistant",
                "tool" => "Tool",
                _ => "System",
            };
            let preview: String = entry.content.chars().take(500).collect();
            let suffix = if entry.content.len() > 500 { "..." } else { "" };
            let tool_info = entry.tool_name.as_ref().map(|t| format!(" [{}]", t)).unwrap_or_default();
            parts.push(format!("{}{}: {}{}", role_label, tool_info, preview, suffix));
        }

        Ok(parts.join("\n"))
    }

    /// Get total entry count.
    pub fn total_entries(&self) -> Result<usize, String> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM conversations", [], |row| row.get(0),
        ).map_err(|e| format!("Count failed: {}", e))?;
        Ok(count as usize)
    }

    // ── Task Checkpoint CRUD ──────────────────────────────────────

    /// Save or update a task checkpoint (INSERT OR REPLACE).
    pub fn save_checkpoint(&self, cp: &TaskCheckpoint) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO task_checkpoints \
             (id, session_id, model_name, user_message, history_json, iteration, tool_summary, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                cp.id, cp.session_id, cp.model_name, cp.user_message,
                cp.history_json, cp.iteration as i64, cp.tool_summary,
                cp.created_at, cp.updated_at,
            ],
        ).map_err(|e| format!("Failed to save checkpoint: {}", e))?;
        Ok(())
    }

    /// List all checkpoints, most recently updated first.
    pub fn list_checkpoints(&self) -> Result<Vec<TaskCheckpoint>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, session_id, model_name, user_message, history_json, \
                    iteration, tool_summary, created_at, updated_at \
             FROM task_checkpoints ORDER BY updated_at DESC"
        ).map_err(|e| format!("Checkpoint list prepare failed: {}", e))?;

        let cps = stmt.query_map([], |row| {
            Ok(TaskCheckpoint {
                id: row.get(0)?,
                session_id: row.get(1)?,
                model_name: row.get(2)?,
                user_message: row.get(3)?,
                history_json: row.get(4)?,
                iteration: row.get::<_, i64>(5)? as usize,
                tool_summary: row.get(6)?,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
            })
        }).map_err(|e| format!("Checkpoint list query failed: {}", e))?
          .filter_map(|r| r.ok())
          .collect();

        Ok(cps)
    }

    /// Get a single checkpoint by ID.
    pub fn get_checkpoint(&self, id: &str) -> Result<Option<TaskCheckpoint>, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, session_id, model_name, user_message, history_json, \
                    iteration, tool_summary, created_at, updated_at \
             FROM task_checkpoints WHERE id = ?1"
        ).map_err(|e| format!("Checkpoint get prepare failed: {}", e))?;

        let result = stmt.query_row(params![id], |row| {
            Ok(TaskCheckpoint {
                id: row.get(0)?,
                session_id: row.get(1)?,
                model_name: row.get(2)?,
                user_message: row.get(3)?,
                history_json: row.get(4)?,
                iteration: row.get::<_, i64>(5)? as usize,
                tool_summary: row.get(6)?,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
            })
        });

        match result {
            Ok(cp) => Ok(Some(cp)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("Checkpoint get failed: {}", e)),
        }
    }

    /// Delete a checkpoint by ID.
    pub fn delete_checkpoint(&self, id: &str) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM task_checkpoints WHERE id = ?1", params![id])
            .map_err(|e| format!("Failed to delete checkpoint: {}", e))?;
        Ok(())
    }

    /// Delete checkpoints older than `max_age_hours` hours.
    /// Returns the number of deleted rows.
    pub fn cleanup_stale_checkpoints(&self, max_age_hours: i64) -> Result<usize, String> {
        let conn = self.conn.lock().unwrap();
        let deleted = conn.execute(
            "DELETE FROM task_checkpoints WHERE updated_at < datetime('now', ?1)",
            params![format!("-{} hours", max_age_hours)],
        ).map_err(|e| format!("Failed to cleanup checkpoints: {}", e))?;
        if deleted > 0 {
            info!("Cleaned up {} stale checkpoint(s) (older than {}h)", deleted, max_age_hours);
        }
        Ok(deleted)
    }
}
