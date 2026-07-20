use std::fs;
use std::path::PathBuf;

pub fn handle_clean() -> Result<(), String> {
    let target_dir = PathBuf::from("target");
    if target_dir.exists() {
        fs::remove_dir_all(&target_dir)
            .map_err(|e| format!("Không thể xóa thư mục target: {}", e))?;
        println!("Đã xóa thư mục target");
    } else {
        println!("Thư mục target không tồn tại");
    }
    Ok(())
}
