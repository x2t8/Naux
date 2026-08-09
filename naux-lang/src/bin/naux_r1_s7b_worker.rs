use std::io::{self, Write};
use std::process::ExitCode;
#[cfg(debug_assertions)]
use std::process::{Command, Stdio};

const EXIT_USAGE: u8 = 64;
const EXIT_WORKER: u8 = 70;
const EXIT_OUTPUT: u8 = 74;

fn main() -> ExitCode {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let Some(case_ordinal) = arguments.next() else {
        eprintln!("naux-r1-s7b-worker requires exactly one case ordinal");
        return ExitCode::from(EXIT_USAGE);
    };
    if arguments.next().is_some() {
        eprintln!("naux-r1-s7b-worker accepts exactly one case ordinal");
        return ExitCode::from(EXIT_USAGE);
    }
    let Some(case_ordinal) = case_ordinal.to_str() else {
        eprintln!("naux-r1-s7b-worker case ordinal is not canonical UTF-8");
        return ExitCode::from(EXIT_USAGE);
    };
    let canonical_case_ordinal = case_ordinal;
    let Ok(case_ordinal) = canonical_case_ordinal.parse::<u32>() else {
        eprintln!("naux-r1-s7b-worker case ordinal is not a canonical u32");
        return ExitCode::from(EXIT_USAGE);
    };
    if case_ordinal.to_string() != canonical_case_ordinal {
        eprintln!("naux-r1-s7b-worker case ordinal is not canonical decimal");
        return ExitCode::from(EXIT_USAGE);
    }

    #[cfg(debug_assertions)]
    if let Some(exit) = run_debug_probe(case_ordinal) {
        return exit;
    }

    let frame = match naux::core::emit_x64_native_worker_frame_r1_s7bc(case_ordinal) {
        Ok(frame) => frame,
        Err(error) => {
            eprintln!("naux-r1-s7b-worker failed: {error}");
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
    let mode = std::env::var_os("NAUX_S7B_WORKER_DEBUG_PROBE")?;
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
                .env("NAUX_S7B_WORKER_DEBUG_PROBE", "descendant-holder")
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
            let _ = io::stdout().lock().write_all(b"not-a-canonical-frame");
            Some(ExitCode::SUCCESS)
        }
        "oversized" => {
            let bytes = vec![0_u8; 16_385];
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
            let bytes = vec![0_u8; 16_384];
            let _ = io::stdout().lock().write_all(&bytes);
            Some(ExitCode::SUCCESS)
        }
        "trailing" => {
            let mut frame = naux::core::emit_x64_native_worker_frame_r1_s7bc(case_ordinal).ok()?;
            frame.push(0);
            let _ = io::stdout().lock().write_all(&frame);
            Some(ExitCode::SUCCESS)
        }
        "truncated" => {
            let mut frame = naux::core::emit_x64_native_worker_frame_r1_s7bc(case_ordinal).ok()?;
            frame.pop();
            let _ = io::stdout().lock().write_all(&frame);
            Some(ExitCode::SUCCESS)
        }
        "double-frame" => {
            let frame = naux::core::emit_x64_native_worker_frame_r1_s7bc(case_ordinal).ok()?;
            let mut output = io::stdout().lock();
            let _ = output.write_all(&frame);
            let _ = output.write_all(&frame);
            Some(ExitCode::SUCCESS)
        }
        "valid-abnormal" => {
            let frame = naux::core::emit_x64_native_worker_frame_r1_s7bc(case_ordinal).ok()?;
            let mut output = io::stdout().lock();
            let _ = output.write_all(&frame).and_then(|()| output.flush());
            Some(ExitCode::from(EXIT_WORKER))
        }
        "valid-abort" => {
            let frame = naux::core::emit_x64_native_worker_frame_r1_s7bc(case_ordinal).ok()?;
            let mut output = io::stdout().lock();
            let _ = output.write_all(&frame).and_then(|()| output.flush());
            drop(output);
            std::process::abort()
        }
        "wrong-case" => {
            let wrong_case = if case_ordinal == 0 { 1 } else { 0 };
            let frame = naux::core::emit_x64_native_worker_frame_r1_s7bc(wrong_case).ok()?;
            let _ = io::stdout().lock().write_all(&frame);
            Some(ExitCode::SUCCESS)
        }
        _ => None,
    }
}
