use std::fs;
use std::path::Path;

use crate::cli::new;

/// Scaffold a NAUX project at `path` (default: current directory).
pub fn init_project(path: &str) -> Result<(), String> {
    let root = Path::new(path);
    if root.exists() {
        let mut entries = fs::read_dir(root)
            .map_err(|err| format!("Không đọc được `{}`: {err}", root.display()))?;
        if entries.next().is_some() {
            return Err(format!("Thư mục `{}` không rỗng", root.display()));
        }
    }

    new::scaffold_project(root)?;
    println!("Đã khởi tạo project NAUX tại `{}`", root.display());
    Ok(())
}
