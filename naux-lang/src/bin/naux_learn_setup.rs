//! Native, dependency-free NAUX Learn setup carrier.
//!
//! This binary deliberately stays a thin user-facing layer over the admitted
//! locale and receipt semantics in the main NAUX library. It owns no alternate
//! installation algorithm.

use std::env;
use std::ffi::OsString;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use naux::install_lifecycle::install_with_receipt;
use naux::install_locale::{catalog_for, InstallerCatalog, SUPPORTED_LOCALES};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Default)]
struct Options {
    language: Option<String>,
    prefix: Option<PathBuf>,
    state_directory: Option<PathBuf>,
    assume_yes: bool,
    show_help: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("NAUX Learn Setup: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let options = parse_options(env::args_os().skip(1))?;
    if options.show_help {
        print_help();
        return Ok(());
    }
    if options.assume_yes && options.language.is_none() {
        return Err("--yes requires an explicit --language".into());
    }

    let catalog = select_catalog(options.language.as_deref())?;
    println!("\n{}\n", catalog.render_release_disclosure(VERSION));
    if !options.assume_yes && !confirm_install(&catalog)? {
        println!("{}", catalog.text("action_cancel"));
        return Ok(());
    }

    let executable = env::current_exe()
        .map_err(|error| format!("cannot locate the Setup executable: {error}"))?;
    let bundle = executable
        .parent()
        .ok_or_else(|| "Setup executable has no bundle directory".to_string())?;
    let (default_prefix, default_state) = default_installation_paths()?;
    let prefix = absolute_path(options.prefix.as_deref().unwrap_or(&default_prefix))?;
    let state_directory =
        absolute_path(options.state_directory.as_deref().unwrap_or(&default_state))?;
    create_state_directory(&state_directory)?;

    let receipt = install_with_receipt(bundle, &prefix, &state_directory, catalog.locale())
        .map_err(|error| error.to_string())?;

    println!("\n{}: NAUX Learn {VERSION}", catalog.text("action_finish"));
    println!("language: {}", receipt.locale());
    println!("prefix: {}", receipt.prefix().display());
    println!("receipt: {}", receipt.receipt_path().display());
    println!("bundle-manifest-seal: {}", receipt.bundle_manifest_seal());
    println!("\n{}\n", catalog.render_release_disclosure(VERSION));
    print_first_program(receipt.prefix(), &catalog);
    wait_before_close(options.assume_yes)?;
    Ok(())
}

fn parse_options(arguments: impl Iterator<Item = OsString>) -> Result<Options, String> {
    let mut options = Options::default();
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        if argument == "--yes" {
            if options.assume_yes {
                return Err("--yes may be specified only once".into());
            }
            options.assume_yes = true;
        } else if argument == "--help" || argument == "-h" {
            options.show_help = true;
        } else if argument == "--language" {
            let value = arguments
                .next()
                .ok_or_else(|| "--language requires a locale".to_string())?;
            let value = value
                .into_string()
                .map_err(|_| "--language must be valid Unicode".to_string())?;
            set_once(&mut options.language, value, "language")?;
        } else if argument == "--prefix" {
            let value = arguments
                .next()
                .ok_or_else(|| "--prefix requires a path".to_string())?;
            set_once(&mut options.prefix, PathBuf::from(value), "prefix")?;
        } else if argument == "--state-directory" {
            let value = arguments
                .next()
                .ok_or_else(|| "--state-directory requires a path".to_string())?;
            set_once(
                &mut options.state_directory,
                PathBuf::from(value),
                "state-directory",
            )?;
        } else {
            return Err(format!(
                "unknown argument `{}`; use --help",
                argument.to_string_lossy()
            ));
        }
    }
    if options.show_help
        && (options.language.is_some()
            || options.prefix.is_some()
            || options.state_directory.is_some()
            || options.assume_yes)
    {
        return Err("--help cannot be combined with installation options".into());
    }
    Ok(options)
}

fn set_once<T>(slot: &mut Option<T>, value: T, label: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("--{label} may be specified only once"));
    }
    Ok(())
}

fn select_catalog(explicit: Option<&str>) -> Result<InstallerCatalog, String> {
    if let Some(locale) = explicit {
        return catalog_for(locale).map_err(|error| error.to_string());
    }
    if !io::stdin().is_terminal() {
        return Err("interactive language selection requires a terminal; use --language".into());
    }

    println!("NAUX Learn Setup — Select language / Chọn ngôn ngữ");
    for (index, locale) in SUPPORTED_LOCALES.iter().enumerate() {
        println!(
            "  {}. {} ({})",
            index + 1,
            locale.language_name,
            locale.code
        );
    }
    print!("> ");
    io::stdout()
        .flush()
        .map_err(|error| format!("cannot flush the language prompt: {error}"))?;
    let answer = read_answer()?;
    let locale = if answer.is_empty() {
        "en-US"
    } else if let Ok(index) = answer.parse::<usize>() {
        SUPPORTED_LOCALES
            .get(index.checked_sub(1).ok_or_else(|| {
                "language selection must be a number from 1 to 9 or a locale code".to_string()
            })?)
            .map(|locale| locale.code)
            .ok_or_else(|| {
                "language selection must be a number from 1 to 9 or a locale code".to_string()
            })?
    } else {
        answer.as_str()
    };
    catalog_for(locale).map_err(|error| error.to_string())
}

fn confirm_install(catalog: &InstallerCatalog) -> Result<bool, String> {
    println!("[1] {}", catalog.text("action_install"));
    println!("[2] {}", catalog.text("action_cancel"));
    print!("> ");
    io::stdout()
        .flush()
        .map_err(|error| format!("cannot flush the installation prompt: {error}"))?;
    match read_answer()?.as_str() {
        "1" => Ok(true),
        "2" => Ok(false),
        _ => Err("installation selection must be 1 or 2".into()),
    }
}

fn read_answer() -> Result<String, String> {
    let mut answer = String::new();
    let bytes = io::stdin()
        .read_line(&mut answer)
        .map_err(|error| format!("cannot read Setup input: {error}"))?;
    if bytes == 0 {
        return Err("Setup input ended before a selection was made".into());
    }
    Ok(answer.trim().to_string())
}

fn default_installation_paths() -> Result<(PathBuf, PathBuf), String> {
    #[cfg(windows)]
    {
        let local = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| "LOCALAPPDATA is unavailable".to_string())?;
        Ok((
            local.join("Programs/NAUX/Learn").join(VERSION),
            local.join("NAUX/state"),
        ))
    }
    #[cfg(not(windows))]
    {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| "HOME is unavailable".to_string())?;
        let data = env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share"));
        let state = env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/state"));
        Ok((
            data.join("naux-learn").join(VERSION),
            state.join("naux-learn"),
        ))
    }
}

fn absolute_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    env::current_dir()
        .map(|directory| directory.join(path))
        .map_err(|error| format!("cannot resolve relative Setup path: {error}"))
}

fn create_state_directory(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|error| {
        format!(
            "cannot create installation state directory `{}`: {error}",
            path.display()
        )
    })
}

fn print_first_program(prefix: &Path, catalog: &InstallerCatalog) {
    let executable = if cfg!(windows) {
        prefix.join("bin/naux.exe")
    } else {
        prefix.join("bin/naux")
    };
    println!("{}:", catalog.text("action_start"));
    println!(
        "\"{}\" run \"{}\"",
        executable.display(),
        prefix.join("examples/hello.nx").display()
    );
}

fn wait_before_close(noninteractive: bool) -> Result<(), String> {
    if noninteractive || !io::stdin().is_terminal() {
        return Ok(());
    }
    println!("Press Enter to close / Nhấn Enter để đóng...");
    let _ = read_answer()?;
    Ok(())
}

fn print_help() {
    println!("NAUX Learn Setup {VERSION}");
    println!("Usage: naux-learn-setup [--language <locale>] [--prefix <path>] \\");
    println!("  [--state-directory <path>] [--yes]");
    println!("Without options, Setup presents an interactive language and consent flow.");
}

#[cfg(test)]
mod tests {
    use super::{parse_options, SUPPORTED_LOCALES};
    use std::ffi::OsString;
    use std::path::Path;

    fn arguments(values: &[&str]) -> impl Iterator<Item = OsString> {
        values
            .iter()
            .map(OsString::from)
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn noninteractive_install_requires_one_explicit_locale() {
        let options = parse_options(arguments(&[
            "--language",
            "pt-BR",
            "--prefix",
            "/tmp/naux",
            "--state-directory",
            "/tmp/state",
            "--yes",
        ]))
        .unwrap();
        assert_eq!(options.language.as_deref(), Some("pt-BR"));
        assert_eq!(options.prefix.as_deref(), Some(Path::new("/tmp/naux")));
        assert_eq!(
            options.state_directory.as_deref(),
            Some(Path::new("/tmp/state"))
        );
        assert!(options.assume_yes);
        assert_eq!(SUPPORTED_LOCALES.len(), 9);
    }

    #[test]
    fn duplicate_and_unknown_setup_arguments_fail_closed() {
        assert!(parse_options(arguments(&["--yes", "--yes"])).is_err());
        assert!(parse_options(arguments(&["--language", "vi-VN", "--language", "de"])).is_err());
        assert!(parse_options(arguments(&["--magic"])).is_err());
        assert!(parse_options(arguments(&["--help", "--yes"])).is_err());
    }
}
