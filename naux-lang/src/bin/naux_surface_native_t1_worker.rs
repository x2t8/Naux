use std::io::{self, Write};
use std::process::ExitCode;
#[cfg(debug_assertions)]
use std::process::{Command, Stdio};

const EXIT_USAGE: u8 = 64;
const EXIT_WORKER: u8 = 70;
const EXIT_OUTPUT: u8 = 74;
#[cfg(debug_assertions)]
const DEBUG_ENV: &str = "NAUX_SURFACE_T1_WORKER_DEBUG_PROBE";

fn main() -> ExitCode {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let Some(case_ordinal) = arguments.next() else {
        eprintln!("naux-surface-native-t1-worker requires exactly one case ordinal");
        return ExitCode::from(EXIT_USAGE);
    };
    if arguments.next().is_some() {
        eprintln!("naux-surface-native-t1-worker accepts exactly one case ordinal");
        return ExitCode::from(EXIT_USAGE);
    }
    let Some(canonical_case_ordinal) = case_ordinal.to_str() else {
        eprintln!("naux-surface-native-t1-worker ordinal is not canonical UTF-8");
        return ExitCode::from(EXIT_USAGE);
    };
    let Ok(case_ordinal) = canonical_case_ordinal.parse::<u32>() else {
        eprintln!("naux-surface-native-t1-worker ordinal is not a canonical u32");
        return ExitCode::from(EXIT_USAGE);
    };
    if case_ordinal.to_string() != canonical_case_ordinal {
        eprintln!("naux-surface-native-t1-worker ordinal is not canonical decimal");
        return ExitCode::from(EXIT_USAGE);
    }

    #[cfg(debug_assertions)]
    if let Some(exit) = run_debug_probe(case_ordinal) {
        return exit;
    }

    let frame = match naux::thesis_surface_native_process::emit_surface_native_t1_worker_frame(
        case_ordinal,
    ) {
        Ok(frame) => frame,
        Err(error) => {
            eprintln!("naux-surface-native-t1-worker failed: {error}");
            return ExitCode::from(EXIT_WORKER);
        }
    };
    let mut output = io::stdout().lock();
    if output
        .write_all(&frame)
        .and_then(|()| output.flush())
        .is_err()
    {
        return ExitCode::from(EXIT_OUTPUT);
    }
    ExitCode::SUCCESS
}

#[cfg(debug_assertions)]
fn run_debug_probe(case_ordinal: u32) -> Option<ExitCode> {
    let mode = std::env::var_os(DEBUG_ENV)?;
    match mode.to_str()? {
        "abort" => std::process::abort(),
        "abnormal" => Some(ExitCode::from(EXIT_WORKER)),
        "timeout" => {
            std::thread::sleep(std::time::Duration::from_secs(60));
            Some(ExitCode::SUCCESS)
        }
        "descendant-pipe" => {
            let executable = std::env::current_exe().ok()?;
            Command::new(executable)
                .arg(case_ordinal.to_string())
                .env(DEBUG_ENV, "descendant-holder")
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .ok()?;
            Some(ExitCode::SUCCESS)
        }
        "descendant-holder" => {
            std::thread::sleep(std::time::Duration::from_secs(60));
            Some(ExitCode::SUCCESS)
        }
        "missing" => Some(ExitCode::SUCCESS),
        "malformed" => {
            let _ = io::stdout().lock().write_all(b"not-a-surface-t1-frame");
            Some(ExitCode::SUCCESS)
        }
        "oversized" => {
            let bytes = vec![0_u8; 2_049];
            let _ = io::stdout().lock().write_all(&bytes);
            Some(ExitCode::SUCCESS)
        }
        "diagnostics-one-over" => {
            for index in 0..129 {
                eprintln!("diagnostic-{index}");
            }
            Some(ExitCode::SUCCESS)
        }
        "diagnostics-limit" => {
            for index in 0..128 {
                eprintln!("diagnostic-{index}");
            }
            Some(ExitCode::SUCCESS)
        }
        "diagnostic-bytes-limit" => {
            let bytes = vec![b'd'; 16_384];
            let mut diagnostics = io::stderr().lock();
            let _ = diagnostics
                .write_all(&bytes)
                .and_then(|()| diagnostics.flush());
            Some(ExitCode::SUCCESS)
        }
        "diagnostic-bytes-one-over" => {
            let bytes = vec![b'd'; 16_385];
            let mut diagnostics = io::stderr().lock();
            let _ = diagnostics
                .write_all(&bytes)
                .and_then(|()| diagnostics.flush());
            Some(ExitCode::SUCCESS)
        }
        "record-limit" => {
            let bytes = vec![0_u8; 2_048];
            let _ = io::stdout().lock().write_all(&bytes);
            Some(ExitCode::SUCCESS)
        }
        "trailing" => {
            let mut frame = canonical_frame(case_ordinal)?;
            frame.push(0);
            let _ = io::stdout().lock().write_all(&frame);
            Some(ExitCode::SUCCESS)
        }
        "truncated" => {
            let mut frame = canonical_frame(case_ordinal)?;
            frame.pop();
            let _ = io::stdout().lock().write_all(&frame);
            Some(ExitCode::SUCCESS)
        }
        "double-frame" => {
            let frame = canonical_frame(case_ordinal)?;
            let mut output = io::stdout().lock();
            let _ = output.write_all(&frame);
            let _ = output.write_all(&frame);
            Some(ExitCode::SUCCESS)
        }
        "valid-abnormal" => {
            let frame = canonical_frame(case_ordinal)?;
            let mut output = io::stdout().lock();
            let _ = output.write_all(&frame).and_then(|()| output.flush());
            Some(ExitCode::from(EXIT_WORKER))
        }
        "valid-abort" => {
            let frame = canonical_frame(case_ordinal)?;
            let mut output = io::stdout().lock();
            let _ = output.write_all(&frame).and_then(|()| output.flush());
            drop(output);
            std::process::abort()
        }
        "wrong-case" => {
            let wrong_case = if case_ordinal == 0 { 1 } else { 0 };
            let frame = canonical_frame(wrong_case)?;
            let _ = io::stdout().lock().write_all(&frame);
            Some(ExitCode::SUCCESS)
        }
        "resealed-observation" | "resealed-identity" | "resealed-mapping" => {
            let frame =
                naux::thesis_surface_native_process::probe_surface_native_t1_resealed_worker_frame(
                    case_ordinal,
                    mode.to_str()?,
                )
                .ok()?;
            let _ = io::stdout().lock().write_all(&frame);
            Some(ExitCode::SUCCESS)
        }
        _ => None,
    }
}

#[cfg(debug_assertions)]
fn canonical_frame(case_ordinal: u32) -> Option<Vec<u8>> {
    naux::thesis_surface_native_process::emit_surface_native_t1_worker_frame(case_ordinal).ok()
}
