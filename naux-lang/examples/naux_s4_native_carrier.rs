use naux::s4_native_carrier::{
    emit_s4_native_candidate, render_s4_native_candidate, verify_s4_native_candidate,
};

fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("usage: naux-s4-native-carrier");
        std::process::exit(2);
    }
    let evidence = emit_s4_native_candidate().unwrap_or_else(|error| {
        eprintln!("S4 native candidate emission failed: {error}");
        std::process::exit(1);
    });
    verify_s4_native_candidate(&evidence).unwrap_or_else(|error| {
        eprintln!("S4 native candidate replay failed: {error}");
        std::process::exit(1);
    });
    print!("{}", render_s4_native_candidate(&evidence));
}
