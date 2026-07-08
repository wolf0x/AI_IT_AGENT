use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

/// Escape a string for embedding as a Rust string literal.
fn escape_for_rust(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn embed_rules(out_dir: &str) {
    let dest_path = Path::new(out_dir).join("rules_embedded.rs");
    let mut f = fs::File::create(&dest_path).unwrap();

    let rules_dir = Path::new("rules");

    let mut entries: Vec<(String, String)> = Vec::new();

    if rules_dir.exists() {
        for entry in fs::read_dir(rules_dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "yar" || ext == "yara") {
                let name = path.file_name().unwrap().to_string_lossy().to_string();
                let content = fs::read_to_string(&path).unwrap_or_default();
                entries.push((name, content));
            }
        }
    }

    entries.sort_by(|a, b| a.0.cmp(&b.0));

    write!(f, "vec![").unwrap();
    for (name, content) in &entries {
        let escaped = escape_for_rust(content);
        let name_escaped = escape_for_rust(name);
        write!(f, "(\"{}\", \"{}\"),", name_escaped, escaped).unwrap();
    }
    write!(f, "]").unwrap();

    println!("cargo:rerun-if-changed=rules");
}

fn embed_workspace_files(out_dir: &str) {
    let dest_path = Path::new(out_dir).join("embedded_files.rs");
    let mut f = fs::File::create(&dest_path).unwrap();

    let files = ["AGENTS.md", "SOUL.md", "TOOLS.md"];

    write!(f, "&[").unwrap();
    for name in &files {
        let path = Path::new(name);
        if path.exists() {
            let content = fs::read_to_string(path).unwrap_or_default();
            let escaped = escape_for_rust(&content);
            write!(f, "(\"{}\", \"{}\"),", name, escaped).unwrap();
        }
    }
    write!(f, "]").unwrap();

    for name in &files {
        println!("cargo:rerun-if-changed={}", name);
    }
}

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    embed_rules(&out_dir);
    embed_workspace_files(&out_dir);
}
