use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("rules_embedded.rs");
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
        // Escape the content for Rust string literal
        let escaped = content
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t");
        let name_escaped = name
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        write!(f, "(\"{}\", \"{}\"),", name_escaped, escaped).unwrap();
    }
    write!(f, "]").unwrap();

    // Re-run build if rules directory changes
    println!("cargo:rerun-if-changed=rules");
}
