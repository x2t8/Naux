use crate::cli::BundleCommand;
use crate::learn_bundle::{install_learn_bundle, verify_learn_bundle, S1_BUNDLE_VERSION};

pub fn handle_bundle(command: BundleCommand) -> Result<(), String> {
    match command {
        BundleCommand::Verify { path } => {
            let receipt = verify_learn_bundle(&path).map_err(|error| error.to_string())?;
            println!("NAUX Learn bundle {S1_BUNDLE_VERSION}");
            println!("target: {}", receipt.target());
            println!("status: verified");
            println!("manifest-seal: {}", receipt.manifest_seal_hex());
            println!("files: {}", receipt.file_count());
            println!("bytes: {}", receipt.total_bytes());
            Ok(())
        }
        BundleCommand::Install { path, prefix } => {
            let receipt =
                install_learn_bundle(&path, &prefix).map_err(|error| error.to_string())?;
            println!("NAUX Learn bundle {S1_BUNDLE_VERSION}");
            println!("target: {}", receipt.target());
            println!("status: installed");
            println!("prefix: {}", receipt.prefix().display());
            println!("manifest-seal: {}", receipt.manifest_seal_hex());
            println!("files: {}", receipt.file_count());
            println!("bytes: {}", receipt.total_bytes());
            Ok(())
        }
    }
}
