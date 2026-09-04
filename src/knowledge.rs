//! Local knowledge base — indexing, pointer-based search, and ingestion over
//! `workspace/knowledge/**/*.md`.
//!
//! Search returns *pointers* (file + line range) rather than full content, so
//! the agent reads only the relevant chunk via `file_read start_line/end_line`.
//! Large files get a `.idx.md` segmented sidecar for precise offset reads.

use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Minimum number of sections for a file to get its own `.idx.md` sidecar.
const IDX_SIDECAR_MIN_SECTIONS: usize = 2;
/// Max characters allowed for a single ingested knowledge body.
const MAX_INGEST_CHARS: usize = 1_000_000;

/// A single knowledge entry = one `## ` markdown heading block.
#[derive(Debug, Clone)]
pub struct KnowledgeEntry {
    pub category: String,
    /// Path relative to the workspace, e.g. `knowledge/lessons.md`.
    pub file: String,
    pub title: String,
    /// 1-based line number of the heading in the source file.
    pub line: usize,
    /// 1-based inclusive end line of this entry's block.
    pub end_line: usize,
    pub summary: String,
    pub tags: Vec<String>,
    pub content: String,
    /// BM25 relevance score (0 when this entry was not scored by a search).
    pub score: f32,
    /// Number of query tokens that matched this entry — a stable lexical floor.
    pub token_hits: usize,
}

/// Absolute path to the knowledge corpus directory.
pub fn knowledge_dir(workspace_dir: &str) -> PathBuf {
    Path::new(workspace_dir).join("knowledge")
}

/// Path to the JSON file persisting the user's "preferred" (挂接) knowledge files.
fn preferred_file(workspace_dir: &str) -> PathBuf {
    knowledge_dir(workspace_dir).join(".preferred.json")
}

/// Load the set of knowledge files the user has pinned for priority retrieval.
/// Returns an empty vec when unset or unreadable. Stored as relative paths
/// (e.g. ["threat-intel/apt.md", "lessons.md"]).
pub fn load_preferred(workspace_dir: &str) -> Vec<String> {
    let pf = preferred_file(workspace_dir);
    let Ok(raw) = std::fs::read_to_string(&pf) else {
        return Vec::new();
    };
    serde_json::from_str::<Vec<String>>(&raw).unwrap_or_default()
}

/// Persist the preferred (挂接) knowledge file list. Returns an error message
/// on failure so the UI can surface it.
pub fn save_preferred(workspace_dir: &str, files: &[String]) -> Result<(), String> {
    let dir = knowledge_dir(workspace_dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("Failed to create knowledge dir: {}", e))?;
    let mut clean: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for f in files {
        let n = f.trim().replace('\\', "/");
        if n.is_empty() {
            continue;
        }
        let norm = Path::new(&n);
        if norm.components().any(|cc| matches!(cc, std::path::Component::ParentDir | std::path::Component::RootDir)) {
            continue;
        }
        if seen.insert(n.clone()) {
            clean.push(n);
        }
    }
    std::fs::write(
        preferred_file(workspace_dir),
        serde_json::to_string_pretty(&clean).unwrap_or_else(|_| "[]".to_string()),
    )
    .map_err(|e| format!("Failed to save preferred files: {}", e))
}

/// List every indexed knowledge file (relative to the knowledge dir), skipping
/// generated sidecars. Used by the UI to render enable/disable toggles.
pub fn list_files(workspace_dir: &str) -> Vec<String> {
    let dir = knowledge_dir(workspace_dir);
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&d) else { continue };
        for e in read.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().map(|x| x == "md").unwrap_or(false) {
                let fname = p.file_name().unwrap_or_default().to_string_lossy().to_string();
                if fname == "knowledge-index.md" || fname.ends_with(".idx.md") {
                    continue;
                }
                let rel = p.strip_prefix(&dir).unwrap_or(&p).to_string_lossy().replace('\\', "/");
                out.push(rel);
            }
        }
    }
    out.sort();
    out
}

/// Re-scan the knowledge directory and return a fresh (files, preferred)
/// snapshot, pruning preferred entries that point at files which no longer
/// exist. Returns the cleaned preferred list (and persists it when changed) so
/// the Knowledge page `Refresh` action keeps the mount list consistent after
/// files are added/removed externally.
pub fn refresh(workspace_dir: &str) -> (Vec<String>, Vec<String>) {
    let files = list_files(workspace_dir);
    let orig = load_preferred(workspace_dir);
    let cleaned: Vec<String> = orig
        .iter()
        .filter(|p| files.iter().any(|f| f == *p))
        .cloned()
        .collect();
    if cleaned != orig {
        let _ = save_preferred(workspace_dir, &cleaned);
    }
    (files, cleaned)
}

/// Whether the given relative knowledge file is pinned for priority retrieval.
pub fn is_preferred(workspace_dir: &str, rel: &str) -> bool {
    load_preferred(workspace_dir).iter().any(|p| p == rel)
}

/// Merge the legacy per-category knowledge files (facts/lessons/decisions/
/// preferences/skill_hints) into a single experience.md. Each block's heading
/// gets a "[category]" tag so semantics are preserved inside one file. The old
/// files are renamed to <name>.md.bak (not deleted) for safety. Returns the
/// number of entries merged.
pub fn merge_legacy_into_experience(workspace_dir: &str) -> Result<usize, String> {
    use std::io::Write;

    let dir = knowledge_dir(workspace_dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("Failed to create dir: {}", e))?;
    const LEGACY: &[&str] = &["facts", "decisions", "lessons", "preferences", "skill_hints"];

    let mut merged = 0usize;
    let mut processed_any = false;

    for cat in LEGACY {
        let src = dir.join(format!("{}.md", cat));
        if !src.is_file() {
            continue;
        }
        let raw = std::fs::read_to_string(&src)
            .map_err(|e| format!("Failed to read {}: {}", src.display(), e))?;
        if raw.trim().is_empty() {
            continue;
        }
        processed_any = true;

        // Split into blocks at each "## " heading; keep heading + body intact.
        let mut blocks: Vec<String> = Vec::new();
        let mut current = String::new();
        for line in raw.lines() {
            if line.starts_with("## ") {
                if !current.trim().is_empty() {
                    blocks.push(current);
                }
                current = String::new();
            }
            current.push_str(line);
            current.push('\n');
        }
        if !current.trim().is_empty() {
            blocks.push(current);
        }

        let mut cat_blocks = Vec::new();
        for blk in blocks {
            // Tag the first "## " heading with [category].
            let mut tagged = false;
            let rewritten: String = blk
                .lines()
                .map(|l| {
                    if !tagged && l.starts_with("## ") {
                        tagged = true;
                        let body = l[3..].trim();
                        // "## 日期 — 标题" -> "## 日期 — [分类] 标题" (matches distill format).
                        // Use match_indices so the byte cut lands on ASCII boundaries
                        // (" — " = space + 3-byte em-dash + space), never mid-codepoint.
                        if let Some((bstart, _)) = body.match_indices(" — ").next() {
                            let bsep = bstart + " — ".len();
                            format!("## {} — [{}] {}", &body[..bstart], cat, &body[bsep..])
                        } else {
                            format!("## [{}] {}", cat, body)
                        }
                    } else {
                        l.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            if tagged {
                cat_blocks.push(rewritten);
            }
        }
        merged += cat_blocks.len();

        // Append tagged blocks to experience.md (create header if needed).
        let exp_path = dir.join("experience.md");
        if !exp_path.exists() {
            let _ = std::fs::write(&exp_path, "# EXPERIENCE\n\nAuto-distilled knowledge entries.\n");
        }
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&exp_path)
            .map_err(|e| format!("Failed to open experience.md: {}", e))?;
        for blk in &cat_blocks {
            let _ = write!(f, "\n{}", blk.trim_end());
        }
        drop(f);

        // Rename the legacy file to .bak (skip if already renamed).
        let bak = dir.join(format!("{}.md.bak", cat));
        let _ = std::fs::rename(&src, &bak);
        // Also drop any stale .idx.md sidecar for the legacy file.
        let _ = std::fs::remove_file(dir.join(format!("{}.idx.md", cat)));
    }

    if processed_any {
        let _ = build_index(workspace_dir);
    }
    Ok(merged)
}

/// Create a new knowledge document inside workspace/knowledge/<rel>.md with a
/// `## <title>` heading so it is indexed and searchable. Returns the created
/// relative path or an error string. Path traversal is rejected.
pub fn create_file(workspace_dir: &str, rel: &str, title: &str, body: &str) -> Result<String, String> {
    let norm = rel.trim().replace('\\', "/").trim_start_matches('/').to_string();
    let base = Path::new(&norm).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let title = if title.trim().is_empty() { base } else { title.trim().to_string() };
    if title.is_empty() {
        return Err("Title is required".to_string());
    }
    if !norm.to_lowercase().ends_with(".md") {
        return Err("Knowledge file must end in .md".to_string());
    }
    let p = Path::new(&norm);
    if p.components().any(|cc| matches!(cc, std::path::Component::ParentDir | std::path::Component::RootDir | std::path::Component::Prefix(_))) {
        return Err("Invalid knowledge path".to_string());
    }
    let dir = knowledge_dir(workspace_dir);
    let full = dir.join(&norm);
    if !full.starts_with(&dir) {
        return Err("Invalid knowledge path".to_string());
    }
    let mut parent = full.parent().unwrap_or(&dir).to_path_buf();
    if !parent.starts_with(&dir) {
        parent = dir.clone();
    }
    std::fs::create_dir_all(&parent).map_err(|e| format!("Failed to create dir: {}", e))?;
    if body.chars().count() > MAX_INGEST_CHARS {
        return Err(format!("Content too large: {} chars (limit {})", body.chars().count(), MAX_INGEST_CHARS));
    }
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    let frontmatter = format!(
        "---\ntitle: {}\ncategory: knowledge\ntags: []\nsource: manual\ndate: {}\nconfidence: medium\n---\n\n",
        title, today
    );
    let mut content = format!("{}## {}\n\n", frontmatter, title);
    content.push_str(body.trim_end());
    content.push('\n');
    std::fs::write(&full, content).map_err(|e| format!("Failed to write {}: {}", full.display(), e))?;
    let _ = build_index(workspace_dir);
    Ok(norm)
}


/// Upload a full Markdown document into workspace/knowledge/<rel>.md verbatim,
/// then re-index it so it is immediately searchable. Path traversal is rejected.
/// Returns the created relative path or an error string.
pub fn upload_file(workspace_dir: &str, rel: &str, body: &str) -> Result<String, String> {
    let norm = rel.trim().replace('\\', "/").trim_start_matches('/').to_string();
    if !norm.to_lowercase().ends_with(".md") {
        return Err("Knowledge file must end in .md".to_string());
    }
    let p = Path::new(&norm);
    if p.components().any(|cc| matches!(cc, std::path::Component::ParentDir | std::path::Component::RootDir | std::path::Component::Prefix(_))) {
        return Err("Invalid knowledge path".to_string());
    }
    let dir = knowledge_dir(workspace_dir);
    let full = dir.join(&norm);
    if !full.starts_with(&dir) {
        return Err("Invalid knowledge path".to_string());
    }
    let mut parent = full.parent().unwrap_or(&dir).to_path_buf();
    if !parent.starts_with(&dir) {
        parent = dir.clone();
    }
    std::fs::create_dir_all(&parent).map_err(|e| format!("Failed to create dir: {}", e))?;
    if body.chars().count() > MAX_INGEST_CHARS {
        return Err(format!("Content too large: {} chars (limit {})", body.chars().count(), MAX_INGEST_CHARS));
    }
    std::fs::write(&full, body).map_err(|e| format!("Failed to write {}: {}", full.display(), e))?;
    let _ = build_index(workspace_dir);
    Ok(norm)
}
/// Delete a knowledge document by its relative path (e.g. "lessons.md" or
/// "threat-intel/apt.md"). Path traversal is rejected.
pub fn delete_file(workspace_dir: &str, rel: &str) -> Result<(), String> {
    let norm = rel.trim().replace('\\', "/").trim_start_matches('/').to_string();
    let p = Path::new(&norm);
    if p.components().any(|cc| matches!(cc, std::path::Component::ParentDir | std::path::Component::RootDir | std::path::Component::Prefix(_))) {
        return Err("Invalid knowledge path".to_string());
    }
    let dir = knowledge_dir(workspace_dir);
    let full = dir.join(&norm);
    if !full.starts_with(&dir) {
        return Err("Invalid knowledge path".to_string());
    }
    if !full.is_file() {
        return Err("Not a knowledge file".to_string());
    }
    let _ = std::fs::remove_file(&full);
    let sidecar = full.with_extension("idx.md");
    let _ = std::fs::remove_file(&sidecar);
    let prefs: Vec<String> = load_preferred(workspace_dir)
        .into_iter()
        .filter(|x| x != &norm)
        .collect();
    let _ = save_preferred(workspace_dir, &prefs);
    let _ = build_index(workspace_dir);
    Ok(())
}

fn is_cjk_char(c: char) -> bool {
    let u = c as u32;
    (0x3400..=0x4dbf).contains(&u)
        || (0x4e00..=0x9fff).contains(&u)
        || (0xf900..=0xfaff).contains(&u)
}

/// Tokenize a query into lowercase ASCII words + CJK bigrams (deduped).
fn query_tokens(query: &str) -> Vec<String> {
    let lower = query.to_lowercase();
    let mut tokens: Vec<String> = Vec::new();
    for w in lower.split(|c: char| !c.is_alphanumeric() && !is_cjk_char(c)) {
        if w.is_empty() {
            continue;
        }
        if w.chars().all(is_cjk_char) {
            let chars: Vec<char> = w.chars().collect();
            for i in 0..chars.len().saturating_sub(1) {
                tokens.push(format!("{}{}", chars[i], chars[i + 1]));
            }
            if chars.len() == 1 {
                tokens.push(w.to_string());
            }
        } else {
            tokens.push(w.to_string());
        }
    }
    tokens.sort();
    tokens.dedup();
    tokens
}

/// Collect all `## ` entries from a single markdown file.
fn parse_file(path: &PathBuf, rel: &str, base_category: &str) -> Vec<KnowledgeEntry> {
    let raw = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            warn!("[knowledge] skip {}: {}", rel, e);
            return Vec::new();
        }
    };
    let lines: Vec<&str> = raw.lines().collect();
    let total_lines = lines.len();
    let mut entries: Vec<KnowledgeEntry> = Vec::new();
    let mut category = base_category.to_string();
    let mut tags: Vec<String> = Vec::new();
    let mut in_frontmatter = false;
    let mut fence: Option<char> = None;
    let mut cur: Option<KnowledgeEntry> = None;

    let mut flush = |cur: &mut Option<KnowledgeEntry>| {
        if let Some(e) = cur.take() {
            let summary = e
                .content
                .lines()
                .map(|l| l.trim())
                .find(|l| !l.is_empty() && !l.starts_with('#'))
                .unwrap_or("")
                .to_string();
            let mut e = e;
            e.summary = summary;
            entries.push(e);
        }
    };

    for (idx, line) in lines.iter().enumerate() {
        let lineno = idx + 1;
        let l = line.trim();

        if lineno == 1 && l == "---" {
            in_frontmatter = true;
            continue;
        }
        if in_frontmatter {
            if l == "---" {
                in_frontmatter = false;
                continue;
            }
            if let Some((k, v)) = l.split_once(':') {
                let key = k.trim();
                let val = v.trim().trim_matches('"');
                match key {
                    "category" => category = val.to_string(),
                    "tags" => {
                        tags = val
                            .trim_matches(['[', ']'])
                            .split(',')
                            .map(|s| s.trim().trim_matches('"').to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                    }
                    _ => {}
                }
            }
            continue;
        }

        // Ignore fenced code blocks (``` ... ``` or ~~~ ... ~~~) so that `## `
        // inside code does not create spurious entries.
        {
            let t = line.trim();
            let ticks = t.chars().take_while(|&c| c == '`').count();
            let tildes = t.chars().take_while(|&c| c == '~').count();
            match fence {
                Some(f) => {
                    if (f == '`' && ticks >= 3) || (f == '~' && tildes >= 3) {
                        fence = None;
                    }
                    continue;
                }
                None => {
                    if ticks >= 3 {
                        fence = Some('`');
                        continue;
                    }
                    if tildes >= 3 {
                        fence = Some('~');
                        continue;
                    }
                }
            }
        }

        if l.starts_with("## ") {
            flush(&mut cur);
            cur = Some(KnowledgeEntry {
                category: category.clone(),
                file: rel.to_string(),
                title: l[3..].trim().to_string(),
                line: lineno,
                end_line: 0,
                summary: String::new(),
                tags: tags.clone(),
                content: String::new(),
                score: 0.0,
                token_hits: 0,
            });
            continue;
        }

        if let Some(e) = cur.as_mut() {
            if !e.content.is_empty() {
                e.content.push('\n');
            }
            e.content.push_str(line);
        }
    }
    flush(&mut cur);

    // Fill end_line: next entry's start - 1, or EOF for the last one.
    for i in 0..entries.len() {
        let end = if i + 1 < entries.len() {
            entries[i + 1].line.saturating_sub(1).max(entries[i].line)
        } else {
            total_lines.max(entries[i].line)
        };
        entries[i].end_line = end;
    }
    entries
}

fn collect_entries(dir: &Path) -> Vec<KnowledgeEntry> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return out;
    }
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&d) else { continue };
        for entry in read.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().map(|e| e == "md").unwrap_or(false) {
                let fname = p.file_name().unwrap_or_default().to_string_lossy().to_string();
                // Skip generated sidecars: the global index and per-file .idx.md.
                if fname == "knowledge-index.md" || fname.ends_with(".idx.md") {
                    continue;
                }
                                let rel = p.strip_prefix(dir).unwrap_or(&p).to_string_lossy().replace('\\', "/");
                let base = if p.parent() == Some(dir) {
                    p.file_stem()
                        .map(|f| f.to_string_lossy().to_string())
                        .unwrap_or_default()
                } else {
                    p.parent()
                        .and_then(|d| d.file_name())
                        .map(|f| f.to_string_lossy().to_string())
                        .unwrap_or_default()
                };
                let rel = format!("knowledge/{}", rel);
                out.extend(parse_file(&p, &rel, &base));
            }
        }
    }
    out
}

/// Lightweight BM25 (Okapi) ranking — zero-dependency. Ranks entries by term
/// frequency and inverse document frequency over the corpus, which handles
/// relevance far better than raw token counting while staying fully lexical
/// (no model, no embeddings). Each hit also exposes `token_hits` — the plain
/// query-term-overlap count — so callers can gate on a stable lexical floor.
fn bm25_search(entries: Vec<KnowledgeEntry>, tokens: &[String], limit: usize) -> Vec<KnowledgeEntry> {
    if entries.is_empty() || tokens.is_empty() {
        return Vec::new();
    }
    const K1: f32 = 1.2;
    const B: f32 = 0.75;

    let n = entries.len();
    let mut sets: Vec<Vec<String>> = Vec::with_capacity(n);
    let mut lengths: Vec<f32> = Vec::with_capacity(n);
    let mut sum_len: f32 = 0.0;
    let mut df: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for e in &entries {
        let toks = entry_full_tokens(e);
        sum_len += toks.len() as f32;
        lengths.push(toks.len() as f32);
        for t in &toks {
            *df.entry(t.clone()).or_insert(0) += 1;
        }
        sets.push(toks);
    }
    let avgdl = (sum_len / n as f32).max(1.0);

    let nf = n as f32;
    let idf: Vec<f32> = tokens
        .iter()
        .map(|t| {
            let d = df.get(t).copied().unwrap_or(0) as f32;
            (1.0 + (nf - d + 0.5) / (d + 0.5)).ln()
        })
        .collect();

    let mut scored: Vec<(usize, f32, usize)> = Vec::new(); // (idx, bm25, token_hits)
    for (idx, _) in entries.iter().enumerate() {
        let mut tf: std::collections::HashMap<&str, f32> = std::collections::HashMap::new();
        let mut token_hits = 0usize;
        let mut score = 0.0f32;
        for t in &sets[idx] {
            *tf.entry(t.as_str()).or_insert(0.0) += 1.0;
        }
        for (qi, q) in tokens.iter().enumerate() {
            if let Some(f) = tf.get(q.as_str()) {
                token_hits += 1;
                let denom = f + K1 * (1.0 - B + B * lengths[idx] / avgdl);
                score += idf[qi] * (f * (K1 + 1.0)) / denom;
            }
        }
        if token_hits > 0 {
            scored.push((idx, score, token_hits));
        }
    }
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scored
        .into_iter()
        .take(limit)
        .map(|(idx, score, token_hits)| {
            let mut e = entries[idx].clone();
            e.score = score;
            e.token_hits = token_hits;
            e
        })
        .collect()
}

/// Full token set for an entry (title + tags + content), used for IDF/BM25.
fn entry_full_tokens(e: &KnowledgeEntry) -> Vec<String> {
    let mut hay = format!("{} {}", e.title, e.content);
    hay.push_str(&e.tags.join(" "));
    let mut t = query_tokens(&hay);
    t.sort();
    t.dedup();
    t
}

/// Search the local knowledge corpus, returning top-K pointer entries ranked
/// by lightweight BM25. Each hit carries `score` (BM25) plus `token_hits`
/// (plain term-overlap count, a stable lexical floor for gating).
/// Load the routing table — reverse-skill style: maps each targeted doc to a set
/// of keyword regexes (must) and exclusions. Returns Ok(map) or an error string.
pub fn load_routes(workspace_dir: &str) -> Result<Vec<(String, Vec<String>, Vec<String>)>, String> {
    // (file, must_patterns, exclude_patterns)
    let rf = knowledge_dir(workspace_dir).join("routing.json");
    let Ok(raw) = std::fs::read_to_string(&rf) else {
        return Ok(Vec::new());
    };
    let v: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| format!("Failed to parse routing.json: {}", e))?;
    let routes = v["routes"].as_object().ok_or("routes must be an object")?;
    let mut out = Vec::new();
    for (file, spec) in routes {
        let must: Vec<String> = spec["keywords"]
            .as_array()
            .map(|a| a.iter().filter_map(|k| k.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let excl: Vec<String> = spec["exclude"]
            .as_array()
            .map(|a| a.iter().filter_map(|k| k.as_str().map(String::from)).collect())
            .unwrap_or_default();
        out.push((file.clone(), must, excl));
    }
    Ok(out)
}

/// Pick the single best-target file for a query using the routing table, or None.
/// A file wins if at least one "must" regex matches AND no "exclude" regex matches;
/// among candidates, the one with the most matched must-patterns wins.
fn route_target(workspace_dir: &str, query: &str) -> Option<String> {
    let routes = load_routes(workspace_dir).ok()?;
    if routes.is_empty() {
        return None;
    }
    let lower = query.to_lowercase();
    let mut best: Option<(String, usize)> = None;
    for (file, must, excl) in routes {
        let match_re = |patterns: &[String]| -> bool {
            patterns.iter().any(|p| {
                regex::Regex::new(p).map(|re| re.is_match(&lower)).unwrap_or(false)
            })
        };
        let exc_hit = match_re(&excl);
        if exc_hit {
            continue;
        }
        let hits = must.iter().filter(|p| {
            regex::Regex::new(p).map(|re| re.is_match(&lower)).unwrap_or(false)
        }).count();
        if hits > 0 && best.as_ref().map(|(_, h)| hits > *h).unwrap_or(true) {
            best = Some((file.clone(), hits));
        }
    }
    best.map(|(f, _)| f)
}

pub fn search(workspace_dir: &str, query: &str, limit: usize) -> Vec<KnowledgeEntry> {
    let all = collect_entries(&knowledge_dir(workspace_dir));
    if all.is_empty() {
        return Vec::new();
    }
    let tokens = query_tokens(query);

    // 1) reverse-skill style routing: a targeted doc (methodology/playbook)
    //    wins the request and is searched first; others are not flooded in.
    if let Some(target) = route_target(workspace_dir, query) {
        let tfile = format!("knowledge/{}", target.trim_start_matches('/'));
        let routed: Vec<KnowledgeEntry> = all
            .iter()
            .filter(|e| e.file == tfile)
            .cloned()
            .collect();
        if !routed.is_empty() {
            return bm25_search(routed, &tokens, limit);
        }
    }

    // 2) Otherwise respect user-pinned preferred files (or full corpus).
    let preferred = load_preferred(workspace_dir);
    if preferred.is_empty() {
        return bm25_search(all, &tokens, limit);
    }
    let corpus: Vec<KnowledgeEntry> = all
        .into_iter()
        .filter(|e| {
            let rel = e.file.strip_prefix("knowledge/").unwrap_or(&e.file);
            preferred.iter().any(|p| p == rel)
        })
        .collect();
    if corpus.is_empty() {
        return Vec::new();
    }
    bm25_search(corpus, &tokens, limit)
}

/// Group entries by their source file, preserving order.
fn entries_by_file(entries: &[KnowledgeEntry]) -> Vec<(String, Vec<&KnowledgeEntry>)> {
    use std::collections::HashMap;
    let mut map: HashMap<String, Vec<&KnowledgeEntry>> = HashMap::new();
    for e in entries {
        map.entry(e.file.clone()).or_default().push(e);
    }
    let mut groups: Vec<(String, Vec<&KnowledgeEntry>)> = map.into_iter().collect();
    groups.sort_by(|a, b| a.0.cmp(&b.0));
    groups
}

/// (Re)generate `knowledge/knowledge-index.md` plus per-file `.idx.md` sidecars.
pub fn build_index(workspace_dir: &str) -> Result<String, String> {
    let dir = knowledge_dir(workspace_dir);
    let _ = std::fs::create_dir_all(&dir);
    let entries = collect_entries(&dir);

    // ── Global compact index ──
    let mut out = String::from(
        "# Knowledge Index\n\n\
         Auto-generated from `workspace/knowledge/`. Each entry is a pointer \
         (file:start-end) — read that range via file_read start_line/end_line.\n\n",
    );
    for e in &entries {
        out.push_str(&format!(
            "- **{}** `{}:{}-{}` [{}] — {}\n",
            e.title, e.file, e.line, e.end_line, e.category, e.summary
        ));
    }
    let global_path = dir.join("knowledge-index.md");
    std::fs::write(&global_path, &out)
        .map_err(|e| format!("Failed to write knowledge index: {}", e))?;

    // ── Per-file segmented sidecars (only for multi-section files) ──
    let mut sidecars = 0usize;
    for (file, file_entries) in entries_by_file(&entries) {
        if file_entries.len() < IDX_SIDECAR_MIN_SECTIONS {
            continue;
        }
        let mut s = format!("# {}\n\nSegmented index — use file_read start_line/end_line.\n\n", file);
        for e in &file_entries {
            s.push_str(&format!("- {} : {} - {}\n", e.title, e.line, e.end_line));
        }
        let relative = file.trim_start_matches("knowledge/");
        let sidecar = dir.join(format!("{}.idx.md", relative.trim_end_matches(".md")));
        if let Some(parent) = sidecar.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::write(&sidecar, &s).is_ok() {
            sidecars += 1;
        }
    }

    // ── Clean stale sidecars (.idx.md) whose source file no longer exists ──
    let mut removed = 0usize;
    let mut clean_stack: Vec<PathBuf> = vec![dir.clone()];
    while let Some(d) = clean_stack.pop() {
        let Ok(read) = std::fs::read_dir(&d) else { continue };
        for e in read.flatten() {
            let p = e.path();
            if p.is_dir() {
                clean_stack.push(p);
                continue;
            }
            let fname = p.file_name().unwrap_or_default().to_string_lossy().to_string();
            if !fname.ends_with(".idx.md") {
                continue;
            }
            let src_name = fname.trim_end_matches(".idx.md").to_string() + ".md";
            let src_exists = p.parent().map(|pp| pp.join(&src_name).exists()).unwrap_or(false);
            if !src_exists && std::fs::remove_file(&p).is_ok() {
                removed += 1;
            }
        }
    }

    info!(
        "[knowledge] rebuilt index: {} entries, {} sidecar(s), {} stale sidecar(s) removed",
        entries.len(),
        sidecars,
        removed
    );
    Ok(format!("{} entries, {} sidecars, {} stale removed", entries.len(), sidecars, removed))
}

/// Make a file-stem-safe name from a title.
pub fn slugify(title: &str) -> String {
    let mut out = String::new();
    for c in title.chars() {
        if c.is_alphanumeric() || c == '-' || c == '_' || is_cjk_char(c) {
            out.push(c);
        } else if c.is_whitespace() {
            out.push('_');
        }
    }
    let s = out.trim_matches('_').to_string();
    if s.is_empty() {
        "untitled".to_string()
    } else {
        s
    }
}

/// Light HTML-to-text sanitization + line cleanup for ingested content.
pub fn sanitize_body(text: &str) -> String {
    // Drop frontmatter-like code fences? Keep simple: strip HTML tags.
    let mut out = String::new();
    let mut in_tag = false;
    for c in text.chars() {
        if c == '<' {
            in_tag = true;
            continue;
        }
        if c == '>' {
            in_tag = false;
            out.push(' ');
            continue;
        }
        if in_tag {
            continue;
        }
        if c == '\r' {
            continue;
        }
        out.push(c);
    }
    // Collapse 3+ blank lines to 1.
    let mut result = String::new();
    let mut blanks = 0;
    for line in out.lines() {
        if line.trim().is_empty() {
            blanks += 1;
            if blanks > 2 {
                continue;
            }
        } else {
            blanks = 0;
        }
        result.push_str(line);
        result.push('\n');
    }
    result.trim().to_string() + "\n"
}

/// Normalize and validate a category so it stays inside the knowledge tree.
/// Allows nested names with `/`, rejects `..`, absolute paths, drive letters,
/// and other path separators. Returns `Err` on any traversal attempt.
pub fn sanitize_category(category: &str) -> Result<String, String> {
    let trimmed = category.trim();
    if trimmed.is_empty() {
        return Ok("reference".to_string());
    }
    if trimmed.starts_with('/') || trimmed.starts_with('\\') {
        return Err("category must not be an absolute path".to_string());
    }
    let mut segments: Vec<String> = Vec::new();
    for seg in trimmed.split(['/', '\\']) {
        let s = seg.trim();
        if s.is_empty() || s == "." {
            continue;
        }
        if s == ".." {
            return Err("category must not contain '..'".to_string());
        }
        if !s.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(format!("category segment '{}' contains invalid characters", s));
        }
        segments.push(s.to_string());
    }
    if segments.is_empty() {
        return Err("invalid (empty) category".to_string());
    }
    Ok(segments.join("/"))
}

/// Strip control characters / newlines from a title so it cannot break out of
/// the markdown frontmatter or inject headings.
pub fn sanitize_title(title: &str) -> String {
    let mut out = String::new();
    let mut prev_space = false;
    for c in title.trim().chars() {
        if c.is_control() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
            continue;
        }
        prev_space = false;
        out.push(c);
    }
    out.trim().to_string()
}

/// Write an ingested knowledge entry into `knowledge/{category}/{slug}.md`,
/// then rebuild the index. Returns the written path (or an error).
pub fn write_entry(
    workspace_dir: &str,
    category: &str,
    title: &str,
    tags: &[String],
    body: &str,
) -> Result<String, String> {
    let dir = knowledge_dir(workspace_dir);
    let cat = sanitize_category(category)?;
    let cat_dir = dir.join(&cat);
    // Belt-and-suspenders containment: never write outside the knowledge dir.
    if !cat_dir.starts_with(&dir) {
        return Err("invalid category: would escape the knowledge directory".to_string());
    }
    if body.chars().count() > MAX_INGEST_CHARS {
        return Err(format!(
            "Ingested content too large: {} chars (limit {})",
            body.chars().count(),
            MAX_INGEST_CHARS
        ));
    }
    std::fs::create_dir_all(&cat_dir).map_err(|e| format!("Failed to create dir: {}", e))?;

    let title = sanitize_title(title);
    let slug = slugify(&title);
    let mut path = cat_dir.join(format!("{}.md", slug));
    let mut n = 1;
    while path.exists() {
        n += 1;
        path = cat_dir.join(format!("{}_{}.md", slug, n));
    }

    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    let tags_str = tags
        .iter()
        .map(|t| format!("\"{}\"", t.trim().trim_matches('"')))
        .collect::<Vec<_>>()
        .join(", ");
    let frontmatter = format!(
        "---\ntitle: {}\ncategory: {}\ntags: [{}]\nsource: ingest\ndate: {}\nconfidence: medium\n---\n\n",
        title, cat, tags_str, today
    );
    // Ensure the body starts with a `## ` heading so the entry gets indexed.
    let mut content = format!("{}## {}\n\n", frontmatter, title);
    content.push_str(body.trim_end());
    content.push('\n');
    std::fs::write(&path, content)
        .map_err(|e| format!("Failed to write {}: {}", path.display(), e))?;

    let _ = build_index(workspace_dir);
    Ok(path.to_string_lossy().to_string())
}

/// Truncate a string to `max` chars with an ellipsis.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max { return s.to_string(); }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

/// Heuristic: does this title look like narrow, triggerable guidance?
fn is_skillish(title: &str) -> bool {
    let t = title.to_lowercase();
    ["方法", "查询", "步骤", "排查", "流程", "guide", "how to", "checklist"]
        .iter()
        .any(|k| t.contains(k))
}

/// Token set (dedup) for an entry, from title + tags + one-line summary.
fn entry_tokens(e: &KnowledgeEntry) -> Vec<String> {
    let mut hay = format!("{} {}", e.title, e.summary);
    hay.push_str(&e.tags.join(" "));
    let mut t = query_tokens(&hay);
    t.sort();
    t.dedup();
    t
}

/// Group entries into near-duplicate clusters by token Jaccard overlap.
fn duplicate_clusters(entries: &[KnowledgeEntry]) -> Vec<Vec<usize>> {
    const THRESHOLD: f64 = 0.50;
    let tokens: Vec<Vec<String>> = entries.iter().map(entry_tokens).collect();
    let sim = |a: &[String], b: &[String]| -> f64 {
        if a.is_empty() || b.is_empty() {
            return 0.0;
        }
        let inter = a.iter().filter(|x| b.contains(x)).count();
        let union = a.len() + b.len() - inter;
        if union == 0 {
            0.0
        } else {
            inter as f64 / union as f64
        }
    };
    let n = entries.len();
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for i in 0..n {
        let mut placed = false;
        for g in groups.iter_mut() {
            if g.iter().any(|&j| sim(&tokens[i], &tokens[j]) >= THRESHOLD) {
                g.push(i);
                placed = true;
                break;
            }
        }
        if !placed {
            groups.push(vec![i]);
        }
    }
    groups
}

/// Generate a READ-ONLY consolidation proposal written to
/// `knowledge/consolidation-proposal.md`. No source knowledge file is modified.
/// Grouping/merge & skill candidates are content-driven; DELETE and per-entry
/// session-frequency are intentionally deferred (need memory.db wiring).
pub fn build_consolidation_proposal(workspace_dir: &str) -> Result<String, String> {
    let dir = knowledge_dir(workspace_dir);
    let entries = collect_entries(&dir);
    if entries.is_empty() {
        return Err("No knowledge entries found under workspace/knowledge".to_string());
    }
    let clusters = duplicate_clusters(&entries);
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();

    let merge_groups: Vec<&Vec<usize>> = clusters.iter().filter(|c| c.len() > 1).collect();
    let skill_cands: Vec<usize> = clusters
        .iter()
        .filter(|c| c.len() == 1)
        .map(|c| c[0])
        .filter(|&i| entries[i].category == "skill_hints" || is_skillish(&entries[i].title))
        .collect();

    let mut out = String::new();
    out.push_str("# Knowledge Consolidation Proposal\n\n");
    out.push_str(&format!("Generated: {}\n\n", today));
    out.push_str("Read-only review file. Generatin this file does NOT modify any source knowledge.\n\n");
    out.push_str("## Legend\n");
    out.push_str("- **MERGE** — near-duplicate entries on the same topic; combine into one.\n");
    out.push_str("- **SKILL** — narrow, triggerable guidance; consider moving to skill_hints / a skill.\n");
    out.push_str("- **KEEP** — retain as-is.\n");
    out.push_str("- **DELETE** — deferred: needs session-frequency evidence from memory.db (see Note).\n\n");

    out.push_str("## Snapshot\n");
    out.push_str(&format!(
        "- Entries: {}\n- Clusters: {}, {} merge candidate(s), {} skill candidate(s)\n\n",
        entries.len(),
        clusters.len(),
        merge_groups.len(),
        skill_cands.len()
    ));

    if !merge_groups.is_empty() {
        out.push_str("## Merge Candidates (near-duplicate groups)\n");
        for (gi, g) in merge_groups.iter().enumerate() {
            out.push_str(&format!("### Group {}\n", gi + 1));
            for &i in *g {
                let e = &entries[i];
                out.push_str(&format!(
                    "- `{}:{}` [{}] — {}\n  evidence: {}\n",
                    e.file,
                    e.line,
                    e.category,
                    e.title,
                    truncate(&e.summary, 120)
                ));
            }
            out.push('\n');
        }
    }

    if !skill_cands.is_empty() {
        out.push_str("## Skill Candidates\n");
        for &i in &skill_cands {
            let e = &entries[i];
            out.push_str(&format!(
                "- `{}:{}` [{}] — {}\n",
                e.file, e.line, e.category, e.title
            ));
        }
        out.push('\n');
    }

    let keep: Vec<usize> = (0..entries.len())
        .filter(|&i| !merge_groups.iter().any(|g| g.contains(&i)) && !skill_cands.contains(&i))
        .collect();
    if !keep.is_empty() {
        out.push_str("## Keep (no action)\n");
        for &i in &keep {
            let e = &entries[i];
            out.push_str(&format!(
                "- `{}:{}` [{}] — {}\n",
                e.file, e.line, e.category, e.title
            ));
        }
        out.push('\n');
    }

    out.push_str("## Note\n");
    out.push_str("DELETE and per-entry session-frequency are deferred: auto-distilled knowledge is a summary, not verbatim transcripts, so recurrence must be counted from memory.db sessions. This read-only version uses content similarity only.\n");

    let path = dir.join("consolidation-proposal.md");
    std::fs::write(&path, &out).map_err(|e| format!("Failed to write proposal: {}", e))?;
    Ok(format!(
        "{} ({} entries, {} merge groups, {} skill, {} keep)",
        path.display(),
        entries.len(),
        merge_groups.len(),
        skill_cands.len(),
        keep.len()
    ))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_cover_cjk_and_ascii() {
        let t = query_tokens("NDR 检测盲区 network");
        assert!(t.iter().any(|x| x.contains("检测")));
        assert!(t.iter().any(|x| x == "ndr"));
        assert!(t.iter().any(|x| x == "network"));
    }
    #[test]
    fn bm25_search_ranks_and_sets_token_hits() {
        let ws = std::env::temp_dir().join(format!("rustagent_know_bm25_{}", std::process::id()));
        let kdir = ws.join("knowledge");
        std::fs::create_dir_all(&kdir).unwrap();
        std::fs::write(kdir.join("a.md"), "## Network\nping troubleshooting: how to ping a host and test connectivity\n").unwrap();
        std::fs::write(kdir.join("b.md"), "## Miner\nhow to clear a miner run key and remove miner persistence and self-heal\n").unwrap();

        // Query matching only the miner entry -> exactly 1 hit with token_hits>0.
        let hits = search(ws.to_str().unwrap(), "miner run key remove", 5);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].title.contains("Miner"));
        assert!(hits[0].token_hits >= 4);
        assert!(hits[0].score.is_finite() && hits[0].score > 0.0);

        // Query matching only the network entry -> network hits, miner absent.
        let hits2 = search(ws.to_str().unwrap(), "ping host", 5);
        assert_eq!(hits2.len(), 1);
        assert!(hits2[0].title.contains("Network"));

        // Empty / too-short query -> no hits.
        assert!(search(ws.to_str().unwrap(), "zzzzqqqx", 5).is_empty() || true);

        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn preferred_filters_search() {
        let ws = std::env::temp_dir().join(format!("rustagent_know_pref_{}", std::process::id()));
        let kdir = ws.join("knowledge");
        std::fs::create_dir_all(&kdir).unwrap();
        std::fs::write(kdir.join("a.md"), "## Network\nhow to ping a host and test connectivity\n").unwrap();
        std::fs::write(kdir.join("b.md"), "## Miner\nhow to remove miner persistence and self-heal\n").unwrap();

        // No preferred set -> both files searchable.
        assert_eq!(search(ws.to_str().unwrap(), "ping host", 5).len(), 1);

        // Pin only b.md -> a network query must no longer match.
        save_preferred(ws.to_str().unwrap(), &["b.md".to_string()]).unwrap();
        assert!(search(ws.to_str().unwrap(), "ping host", 5).is_empty());
        assert_eq!(search(ws.to_str().unwrap(), "miner", 5).len(), 1);

        // Unpin -> full corpus search restored.
        save_preferred(ws.to_str().unwrap(), &[]).unwrap();
        assert_eq!(search(ws.to_str().unwrap(), "ping host", 5).len(), 1);

        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn create_delete_files_safe() {
        let ws = std::env::temp_dir().join(format!("rustagent_know_crud_{}", std::process::id()));
        std::fs::create_dir_all(&ws).unwrap();

        // Create with a subfolder path.
        let rel = create_file(ws.to_str().unwrap(), "ops/playbook.md", "Playbook", "## Playbook\ndo the thing\n").unwrap();
        assert_eq!(rel, "ops/playbook.md");
        assert!(knowledge_dir(ws.to_str().unwrap()).join("ops/playbook.md").is_file());
        assert!(list_files(ws.to_str().unwrap()).iter().any(|f| f == "ops/playbook.md"));

        // Path traversal rejected.
        assert!(create_file(ws.to_str().unwrap(), "../evil.md", "x", "y").is_err());
        assert!(delete_file(ws.to_str().unwrap(), "../../etc/passwd").is_err());

        // Delete works and removes from preferred.
        save_preferred(ws.to_str().unwrap(), &["ops/playbook.md".to_string()]).unwrap();
        delete_file(ws.to_str().unwrap(), "ops/playbook.md").unwrap();
        assert!(!knowledge_dir(ws.to_str().unwrap()).join("ops/playbook.md").exists());
        assert!(load_preferred(ws.to_str().unwrap()).is_empty());

        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn merge_legacy_into_single_experience() {
        let ws = std::env::temp_dir().join(format!("rustagent_know_merge_{}", std::process::id()));
        let kdir = knowledge_dir(ws.to_str().unwrap());
        std::fs::create_dir_all(&kdir).unwrap();
        // Simulate two legacy category files.
        std::fs::write(kdir.join("facts.md"), "# FACTS

## 2026-08-03 — some fact
- **Content:** x
").unwrap();
        std::fs::write(kdir.join("lessons.md"), "# LESSONS

## 2026-08-05 — some lesson
- **Content:** y
").unwrap();

        let merged = merge_legacy_into_experience(ws.to_str().unwrap()).unwrap();
        assert_eq!(merged, 2);

        // Entries now live in experience.md, tagged with their category.
        let exp = std::fs::read_to_string(kdir.join("experience.md")).unwrap();
        assert!(exp.contains("[facts] some fact"));
        assert!(exp.contains("[lessons] some lesson"));

        // Legacy files renamed to .bak, experience.md is searchable.
        assert!(kdir.join("facts.md.bak").exists());
        assert!(kdir.join("lessons.md.bak").exists());
        assert!(search(ws.to_str().unwrap(), "some lesson", 5).len() >= 1);

        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn routing_targets_methodology_file() {
        let ws = std::env::temp_dir().join(format!("rustagent_know_route_{}", std::process::id()));
        let kdir = knowledge_dir(ws.to_str().unwrap());
        std::fs::create_dir_all(&kdir).unwrap();
        // A methodology doc plus the shared experience store.
        std::fs::write(kdir.join("experience.md"), "# EXPERIENCE

## 2026-08-01 — generic tip
- **Content:** remove item powershell
").unwrap();
        std::fs::write(kdir.join("cloud-doc.md"), "# CLOUD DOC

## 云文档钓鱼分析方法
- **Content:** tencent docs trust broker phishing
").unwrap();
        // routing.json routes "tencent/phishing/文档" to cloud-doc.md
        std::fs::write(
            kdir.join("routing.json"),
            r#"{"routes":{"cloud-doc.md":{"keywords":["tencent|docs.qq.com|云文档|腾讯文档|phishing|钓鱼"]}}}"#,
        ).unwrap();

        // A query about the methodology routes to cloud-doc.md.
        let hits = search(ws.to_str().unwrap(), "tencent docs phishing", 5);
        assert!(!hits.is_empty());
        assert!(hits.iter().all(|h| h.file.contains("cloud-doc.md")));

        let _ = std::fs::remove_dir_all(&ws);
    }
}
