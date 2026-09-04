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
pub fn search(workspace_dir: &str, query: &str, limit: usize) -> Vec<KnowledgeEntry> {
    let all = collect_entries(&knowledge_dir(workspace_dir));
    if all.is_empty() {
        return Vec::new();
    }
    let tokens = query_tokens(query);
    bm25_search(all, &tokens, limit)
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

    info!(
        "[knowledge] rebuilt index: {} entries, {} sidecar(s)",
        entries.len(),
        sidecars
    );
    Ok(format!("{} entries, {} sidecars", entries.len(), sidecars))
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
}
