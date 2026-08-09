use std::io::{self, Write};
use std::process::ExitCode;
#[cfg(debug_assertions)]
use std::process::{Command, Stdio};

const EXIT_USAGE: u8 = 64;
const EXIT_WORKER: u8 = 70;
const EXIT_OUTPUT: u8 = 74;
const DEBUG_ENVIRONMENT: &str = "NAUX_TAIL_ENVELOPED_WORKER_DEBUG_PROBE";

fn main() -> ExitCode {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    if arguments.next().is_some() {
        eprintln!("naux-tail-enveloped-worker accepts no arguments");
        return ExitCode::from(EXIT_USAGE);
    }

    #[cfg(debug_assertions)]
    if let Some(exit) = run_debug_probe() {
        return exit;
    }

    let frame = match naux::core::emit_x64_tail_enveloped_worker_frame_adr0069() {
        Ok(frame) => frame,
        Err(error) => {
            eprintln!("naux-tail-enveloped-worker failed: {error}");
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
fn run_debug_probe() -> Option<ExitCode> {
    let mode = std::env::var_os(DEBUG_ENVIRONMENT)?;
    match mode.to_str()? {
        "abort" => std::process::abort(),
        "abnormal" => Some(ExitCode::from(EXIT_WORKER)),
        "timeout" => {
            std::thread::sleep(std::time::Duration::from_secs(240));
            Some(ExitCode::SUCCESS)
        }
        "descendant-pipe" => {
            let executable = std::env::current_exe().ok()?;
            Command::new(executable)
                .env(DEBUG_ENVIRONMENT, "descendant-holder")
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .ok()?;
            Some(ExitCode::SUCCESS)
        }
        "descendant-holder" => {
            std::thread::sleep(std::time::Duration::from_secs(240));
            Some(ExitCode::SUCCESS)
        }
        "missing" => Some(ExitCode::SUCCESS),
        "malformed" => {
            let _ = io::stdout().lock().write_all(b"not-an-adr0069-frame");
            Some(ExitCode::SUCCESS)
        }
        "oversized" => {
            let bytes = vec![0_u8; naux::core::X64_TAIL_ENVELOPED_IPC_MAX_FRAME_BYTES as usize + 1];
            let _ = io::stdout().lock().write_all(&bytes);
            Some(ExitCode::SUCCESS)
        }
        "diagnostic" => {
            eprintln!("unexpected ADR-0069 diagnostic");
            Some(ExitCode::SUCCESS)
        }
        "trailing" => {
            let mut frame = naux::core::emit_x64_tail_enveloped_worker_frame_adr0069().ok()?;
            frame.push(0);
            let _ = io::stdout().lock().write_all(&frame);
            Some(ExitCode::SUCCESS)
        }
        "truncated" => {
            let mut frame = naux::core::emit_x64_tail_enveloped_worker_frame_adr0069().ok()?;
            frame.pop();
            let _ = io::stdout().lock().write_all(&frame);
            Some(ExitCode::SUCCESS)
        }
        "double-frame" => {
            let frame = naux::core::emit_x64_tail_enveloped_worker_frame_adr0069().ok()?;
            let mut output = io::stdout().lock();
            let _ = output.write_all(&frame);
            let _ = output.write_all(&frame);
            Some(ExitCode::SUCCESS)
        }
        "valid-abnormal" => {
            let frame = naux::core::emit_x64_tail_enveloped_worker_frame_adr0069().ok()?;
            let mut output = io::stdout().lock();
            let _ = output.write_all(&frame).and_then(|()| output.flush());
            Some(ExitCode::from(EXIT_WORKER))
        }
        _ => None,
    }
}
