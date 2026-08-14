use crate::cli::InstallationCommand;
use crate::install_lifecycle::{execute_uninstall, install_with_receipt, plan_uninstall};

pub fn handle_installation(command: InstallationCommand) -> Result<(), String> {
    match command {
        InstallationCommand::Install {
            bundle,
            prefix,
            state_directory,
            language,
        } => {
            let receipt = install_with_receipt(&bundle, &prefix, &state_directory, &language)
                .map_err(|error| error.to_string())?;
            println!("NAUX Learn installation {}", receipt.installation_id());
            println!("status: installed");
            println!("version: {}", crate::cli::NAUX_VERSION);
            println!("target: {}", receipt.target());
            println!("language: {}", receipt.locale());
            println!("prefix: {}", receipt.prefix().display());
            println!("receipt: {}", receipt.receipt_path().display());
            println!("bundle-manifest-seal: {}", receipt.bundle_manifest_seal());
            Ok(())
        }
        InstallationCommand::Uninstall { receipt, dry_run } => {
            let plan = if dry_run {
                plan_uninstall(&receipt)
            } else {
                execute_uninstall(&receipt)
            }
            .map_err(|error| error.to_string())?;
            println!(
                "NAUX Learn installation {}",
                plan.receipt().installation_id()
            );
            println!(
                "status: {}",
                if dry_run {
                    "uninstall-planned"
                } else {
                    "uninstalled"
                }
            );
            println!("prefix: {}", plan.receipt().prefix().display());
            println!("owned-files: {}", plan.files().len());
            println!("owned-directories: {}", plan.directories().len());
            if dry_run {
                for path in plan.files() {
                    println!("remove-file: {}", path.display());
                }
                for path in plan.directories() {
                    println!("remove-directory: {}", path.display());
                }
                println!("remove-receipt: {}", receipt.display());
            }
            Ok(())
        }
        InstallationCommand::VerifyWindowsIcon { executable, icon } => {
            let hash = crate::windows_icon::verify_windows_icon_resource(&executable, &icon)
                .map_err(|error| error.to_string())?;
            println!("Windows icon resource: verified");
            println!("canonical-ico-sha256: {hash}");
            Ok(())
        }
    }
}
