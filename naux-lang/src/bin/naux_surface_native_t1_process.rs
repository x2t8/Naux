use naux::thesis_surface_native_process::{
    emit_surface_native_t1_process_evidence, render_surface_native_t1_process_report,
    surface_native_t1_process_report_hash, verify_surface_native_t1_process_evidence,
};
use std::path::PathBuf;

fn main() {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let Some(worker_path) = arguments.next() else {
        eprintln!("usage: naux-surface-native-t1-process WORKER-PATH");
        std::process::exit(2);
    };
    if arguments.next().is_some() {
        eprintln!("usage: naux-surface-native-t1-process WORKER-PATH");
        std::process::exit(2);
    }
    let worker_path = PathBuf::from(worker_path);
    let evidence = emit_surface_native_t1_process_evidence(&worker_path).unwrap_or_else(|error| {
        eprintln!("surface-native T1 process emission failed: {error}");
        std::process::exit(1);
    });
    verify_surface_native_t1_process_evidence(&evidence, &worker_path).unwrap_or_else(|error| {
        eprintln!("surface-native T1 process replay failed: {error}");
        std::process::exit(1);
    });
    print!("{}", render_surface_native_t1_process_report(&evidence));
    println!(
        "report\t{}",
        surface_native_t1_process_report_hash(&evidence)
    );
    println!("verification\tregenerated-fresh-children");
}
