//! Minimal, receipt-driven Linux manager for NAUX Learn.

#[cfg(unix)]
mod unix {

    use std::env;
    use std::ffi::OsString;
    use std::io::{self, IsTerminal, Write};
    use std::path::PathBuf;

    use naux::learn_bundle::S1_BUNDLE_VERSION;
    use naux::linux_distribution::{execute_linux_uninstall, plan_linux_uninstall};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Command {
        Status,
        List,
        Doctor,
        Uninstall,
        Help,
        Version,
    }

    #[derive(Debug)]
    struct Options {
        command: Command,
        assume_yes: bool,
        dry_run: bool,
    }

    pub(super) fn main() {
        if let Err(error) = run() {
            eprintln!("nauxup: {error}");
            std::process::exit(1);
        }
    }

    fn run() -> Result<(), String> {
        let options = parse_options(env::args_os().skip(1))?;
        match options.command {
            Command::Help => {
                print_help();
                Ok(())
            }
            Command::Version => {
                println!("nauxup {S1_BUNDLE_VERSION}");
                Ok(())
            }
            Command::Status | Command::List | Command::Doctor => show_status(options.command),
            Command::Uninstall => uninstall(options.assume_yes, options.dry_run),
        }
    }

    fn show_status(command: Command) -> Result<(), String> {
        let activation_path = default_activation_path()?;
        let plan = plan_linux_uninstall(&activation_path).map_err(|error| error.to_string())?;
        let activation = plan.activation();
        match command {
            Command::List => println!("NAUX Learn {}", S1_BUNDLE_VERSION),
            Command::Doctor => println!("✓ NAUX Learn {} is intact", S1_BUNDLE_VERSION),
            _ => println!("NAUX Learn {} — installed", S1_BUNDLE_VERSION),
        }
        println!("  toolchain : {}", activation.prefix().display());
        println!("  naux      : {}", activation.naux_launcher().display());
        println!("  nauxup    : {}", activation.nauxup_launcher().display());
        println!("  language  : {}", activation.locale());
        println!("  ownership : {}", activation.receipt_path().display());
        if command == Command::Doctor {
            println!("  checks    : bundle seal, manifest, inventory, modes, launchers, receipts");
        }
        Ok(())
    }

    fn uninstall(assume_yes: bool, dry_run: bool) -> Result<(), String> {
        let activation_path = default_activation_path()?;
        let plan = plan_linux_uninstall(&activation_path).map_err(|error| error.to_string())?;
        println!("NAUX Learn {} uninstall plan", S1_BUNDLE_VERSION);
        println!("  toolchain : {}", plan.activation().prefix().display());
        println!(
            "  launcher  : {}",
            plan.activation().naux_launcher().display()
        );
        println!(
            "  launcher  : {}",
            plan.activation().nauxup_launcher().display()
        );
        println!("  files     : {}", plan.core().files().len());
        println!("  directories: {}", plan.core().directories().len());
        if dry_run {
            println!("Dry run only; nothing was removed.");
            return Ok(());
        }
        if !assume_yes && !confirm_uninstall()? {
            println!("Uninstall cancelled.");
            return Ok(());
        }
        execute_linux_uninstall(&activation_path).map_err(|error| error.to_string())?;
        println!("✓ NAUX Learn {} uninstalled", S1_BUNDLE_VERSION);
        Ok(())
    }

    fn parse_options(arguments: impl Iterator<Item = OsString>) -> Result<Options, String> {
        let mut command = None;
        let mut assume_yes = false;
        let mut dry_run = false;
        for argument in arguments {
            let argument = argument
                .into_string()
                .map_err(|_| "arguments must be valid Unicode".to_string())?;
            match argument.as_str() {
                "status" => set_command(&mut command, Command::Status)?,
                "list" => set_command(&mut command, Command::List)?,
                "doctor" => set_command(&mut command, Command::Doctor)?,
                "uninstall" => set_command(&mut command, Command::Uninstall)?,
                "help" | "-h" | "--help" => set_command(&mut command, Command::Help)?,
                "-V" | "--version" => set_command(&mut command, Command::Version)?,
                "-y" | "--yes" => {
                    if assume_yes {
                        return Err("--yes may be specified only once".into());
                    }
                    assume_yes = true;
                }
                "--dry-run" => {
                    if dry_run {
                        return Err("--dry-run may be specified only once".into());
                    }
                    dry_run = true;
                }
                _ => return Err(format!("unknown argument `{argument}`; use `nauxup help`")),
            }
        }
        let command = command.unwrap_or(Command::Status);
        if command != Command::Uninstall && (assume_yes || dry_run) {
            return Err("--yes and --dry-run are valid only with `nauxup uninstall`".into());
        }
        if assume_yes && dry_run {
            return Err("--yes and --dry-run cannot be combined".into());
        }
        Ok(Options {
            command,
            assume_yes,
            dry_run,
        })
    }

    fn set_command(slot: &mut Option<Command>, command: Command) -> Result<(), String> {
        if slot.replace(command).is_some() {
            return Err("specify exactly one nauxup command".into());
        }
        Ok(())
    }

    fn default_activation_path() -> Result<PathBuf, String> {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| "HOME is unavailable".to_string())?;
        let state = env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/state"));
        Ok(state
            .join("naux/receipts")
            .join(format!("learn-{S1_BUNDLE_VERSION}.tsv")))
    }

    fn confirm_uninstall() -> Result<bool, String> {
        if !io::stdin().is_terminal() {
            return Err("noninteractive uninstall requires --yes".into());
        }
        print!("Remove this installation? [y/N] ");
        io::stdout()
            .flush()
            .map_err(|error| format!("cannot flush uninstall prompt: {error}"))?;
        let mut answer = String::new();
        let count = io::stdin()
            .read_line(&mut answer)
            .map_err(|error| format!("cannot read uninstall answer: {error}"))?;
        if count == 0 {
            return Err("uninstall input ended before a decision was made".into());
        }
        match answer.trim().to_ascii_lowercase().as_str() {
            "" | "n" | "no" => Ok(false),
            "y" | "yes" => Ok(true),
            _ => Err("answer must be Y or N".into()),
        }
    }

    fn print_help() {
        println!("nauxup {S1_BUNDLE_VERSION} — NAUX Learn Linux manager");
        println!("Usage:");
        println!("  nauxup status");
        println!("  nauxup list");
        println!("  nauxup doctor");
        println!("  nauxup uninstall [--dry-run | --yes]");
        println!(
            "\n{S1_BUNDLE_VERSION} intentionally has no network update command. A signed update channel is future work."
        );
    }

    #[cfg(test)]
    mod tests {
        use super::{parse_options, Command};
        use std::ffi::OsString;

        fn arguments(values: &[&str]) -> impl Iterator<Item = OsString> {
            values
                .iter()
                .map(OsString::from)
                .collect::<Vec<_>>()
                .into_iter()
        }

        #[test]
        fn status_is_the_default_and_uninstall_flags_are_bounded() {
            assert_eq!(
                parse_options(arguments(&[])).unwrap().command,
                Command::Status
            );
            let uninstall = parse_options(arguments(&["uninstall", "--yes"])).unwrap();
            assert_eq!(uninstall.command, Command::Uninstall);
            assert!(uninstall.assume_yes);
            assert!(parse_options(arguments(&["doctor", "--yes"])).is_err());
            assert!(parse_options(arguments(&["uninstall", "--yes", "--dry-run"])).is_err());
        }
    }
}

#[cfg(unix)]
fn main() {
    unix::main();
}

#[cfg(not(unix))]
fn main() {
    eprintln!("nauxup: this release manager supports Linux only");
    std::process::exit(1);
}
