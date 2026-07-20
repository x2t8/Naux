use std::process::Command;

pub fn handle_publish() -> Result<(), String> {
    println!("Publishing the Naux crate...");

    let output = Command::new("cargo")
        .arg("publish")
        .output()
        .map_err(|e| e.to_string())?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to publish the crate: {}", stderr));
    }

    println!("Successfully published the crate!");

    Ok(())
}
