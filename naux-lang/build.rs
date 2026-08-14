use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=windows/naux-learn.rc");
    println!("cargo:rerun-if-changed=../assets/langnaux-learn.ico");
    println!("cargo:rerun-if-env-changed=NAUX_WINDOWS_WINDRES");
    println!("cargo:rerun-if-env-changed=NAUX_WINDOWS_MINGW_BIN");

    if env::var_os("CARGO_CFG_TARGET_OS").as_deref() != Some("windows".as_ref()) {
        return;
    }
    if env::var_os("CARGO_CFG_TARGET_ARCH").as_deref() != Some("x86_64".as_ref()) {
        panic!("the NAUX Learn Windows icon resource supports only x86-64");
    }
    // The sealed release producer targets MinGW-w64. Portable library/VM
    // checks on the native MSVC host must not acquire a GNU binutils debt.
    if env::var_os("CARGO_CFG_TARGET_ENV").as_deref() != Some("gnu".as_ref()) {
        return;
    }

    let manifest_dir = required_path("CARGO_MANIFEST_DIR");
    let out_dir = required_path("OUT_DIR");
    let icon_dir = manifest_dir
        .parent()
        .expect("naux-lang must have the workspace root as parent")
        .join("assets");
    let resource_source = manifest_dir.join("windows/naux-learn.rc");
    let resource_object = out_dir.join("naux-learn-icon.o");
    let windres = resolve_windres();

    let status = Command::new(&windres)
        .arg("--include-dir")
        .arg(&icon_dir)
        .arg("--input")
        .arg(&resource_source)
        .arg("--input-format=rc")
        .arg("--output")
        .arg(&resource_object)
        .arg("--output-format=coff")
        .status()
        .unwrap_or_else(|error| panic!("cannot execute {}: {error}", windres.display()));
    if !status.success() {
        panic!(
            "{} rejected the NAUX Learn icon resource",
            windres.display()
        );
    }

    println!(
        "cargo:rustc-link-arg-bin=naux={}",
        resource_object.display()
    );
    println!(
        "cargo:rustc-link-arg-bin=naux-learn-setup={}",
        resource_object.display()
    );
    // GNU PE linking may reselect timestamp insertion after consuming a
    // resource object. Keep this argument after the object so the final PE
    // header remains reproducible even when the caller also pins the policy.
    println!("cargo:rustc-link-arg-bin=naux=-Wl,--no-insert-timestamp");
    println!("cargo:rustc-link-arg-bin=naux-learn-setup=-Wl,--no-insert-timestamp");
}

fn required_path(name: &str) -> PathBuf {
    env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("Cargo did not provide {name}"))
}

fn resolve_windres() -> PathBuf {
    if let Some(path) = env::var_os("NAUX_WINDOWS_WINDRES") {
        return PathBuf::from(path);
    }
    if let Some(directory) = env::var_os("NAUX_WINDOWS_MINGW_BIN") {
        let executable = if cfg!(windows) {
            "x86_64-w64-mingw32-windres.exe"
        } else {
            "x86_64-w64-mingw32-windres"
        };
        return Path::new(&directory).join(executable);
    }
    PathBuf::from("x86_64-w64-mingw32-windres")
}
