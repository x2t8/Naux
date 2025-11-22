use std::fs;
use std::path::Path;

pub fn init_project(path: &str) {
    let dir = Path::new(path);

    if dir.exists() {
        eprintln!("❌ Path `{}` already exists.", path);
        return;
    }

    if let Err(e) = fs::create_dir_all(dir) {
        eprintln!("❌ Failed to create dir `{}`: {}", path, e);
        return;
    }

    let main_content = r#"~ rite
    !say "Hello from NAUX project!"
~ end
"#;
    if let Err(e) = fs::write(dir.join("main.nx"), main_content) {
        eprintln!("❌ Failed to write main.nx: {}", e);
        return;
    }

    let readme_content = r#"# NAUX Project
This is a ritual project scaffolded by `naux init`.
"#;
    if let Err(e) = fs::write(dir.join("README.md"), readme_content) {
        eprintln!("❌ Failed to write README.md: {}", e);
        return;
    }

    println!("✔ Project created at `{}`", path);
}
