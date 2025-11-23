use std::fs;
use std::path::Path;

/// Scaffold a new NAUX project at `path` (default: current dir).
pub fn init_project(path: &str) {
    let dir = Path::new(path);

    if dir.exists() && dir.read_dir().map(|mut d| d.next().is_some()).unwrap_or(false) {
        eprintln!("❌ Path `{}` exists and is not empty. Aborting.", path);
        return;
    }

    if let Err(e) = fs::create_dir_all(dir) {
        eprintln!("❌ Failed to create dir `{}`: {}", path, e);
        return;
    }

    let main_content = r#"~ rite
    !say \"Hello from NAUX project!\"
~ end
"#;
    if let Err(e) = fs::write(dir.join("main.nx"), main_content) {
        eprintln!("❌ Failed to write main.nx: {}", e);
        return;
    }

    let readme_content = r#"# NAUX Project
This is a ritual project scaffolded by `naux init`.

Run:
  naux run main.nx --mode=cli
"#;
    if let Err(e) = fs::write(dir.join("README.md"), readme_content) {
        eprintln!("❌ Failed to write README.md: {}", e);
        return;
    }

    let gitignore_content = "target\n.naux\n";
    let _ = fs::write(dir.join(".gitignore"), gitignore_content);

    println!("✔ Project created at `{}`", path);
}
