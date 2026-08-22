use naux::thesis_surface_native::{
    emit_surface_native_t1, render_surface_native_t1_report, surface_native_t1_report_hash,
    verify_surface_native_t1,
};

fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("usage: naux-surface-native-t1");
        std::process::exit(2);
    }
    let evidence = emit_surface_native_t1().unwrap_or_else(|error| {
        eprintln!("surface-native T1 emission failed: {error}");
        std::process::exit(1);
    });
    verify_surface_native_t1(&evidence).unwrap_or_else(|error| {
        eprintln!("surface-native T1 replay failed: {error}");
        std::process::exit(1);
    });
    print!("{}", render_surface_native_t1_report(&evidence));
    println!("report\t{}", surface_native_t1_report_hash(&evidence));
    println!("verification\tregenerated");
}
