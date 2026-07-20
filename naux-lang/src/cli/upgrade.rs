use std::process::Command;

pub fn handle_upgrade() -> Result<(), String> {
    println!("Checking for updates...");

    let output = Command::new("git")
        .arg("pull")
        .output()
        .map_err(|e| e.to_string())?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to pull updates: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains("Already up to date.") {
        println!("You are already on the latest version.");
    } else {
        println!("Successfully updated!");
        println!("Rebuilding the project...");

        let build_output = Command::new("cargo")
            .arg("build")
            .arg("--release")
            .output()
            .map_err(|e| e.to_string())?;

        if !build_output.status.success() {
            let stderr = String::from_utf8_lossy(&build_output.stderr);
            return Err(format!("Failed to rebuild the project: {}", stderr));
        }

        println!("Successfully rebuilt the project!");
    }

    Ok(())
}
