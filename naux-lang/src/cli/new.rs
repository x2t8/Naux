use std::fs;
use std::path::Path;

pub fn handle_new(name: String) -> Result<(), String> {
    let root = Path::new(&name);
    if root.exists() {
        return Err(format!("Thư mục `{}` đã tồn tại", name));
    }
    fs::create_dir_all(root.join("src")).map_err(|e| format!("Không tạo được src/: {e}"))?;
    fs::create_dir_all(root.join("tests")).map_err(|e| format!("Không tạo được tests/: {e}"))?;
    fs::create_dir_all(root.join("build")).map_err(|e| format!("Không tạo được build/: {e}"))?;
    let main = r#"~ rite
    !say "Welcome to NAUX!"
~ end
"#;
    fs::write(root.join("main.nx"), main).map_err(|e| format!("Không ghi main.nx: {e}"))?;
    let toml = r#"[project]
name = "naux-app"

[run]
engine = "vm"
mode = "cli"
"#;
    fs::write(root.join("naux.toml"), toml).map_err(|e| format!("Không ghi naux.toml: {e}"))?;
    println!("Đã tạo project NAUX tại `{}`", name);
    Ok(())
}
