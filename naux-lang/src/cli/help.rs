pub fn handle_help() -> Result<(), String> {
    println!("Naux Help");
    println!("-------");
    println!("Usage: naux <command>");
    println!();
    println!("Commands:");
    println!("  build        Build the project");
    println!("  check        Type-check the project");
    println!("  clean        Remove the target directory");
    println!("  debug        Debug the project");
    println!("  dev          Developer tooling (ir/disasm/ssa-stats/bench/bytecode)");
    println!("  doctor       Run environment + project health checks");
    println!("  fmt          Format the project");
    println!("  help         Show this help message");
    println!("  ide          Open TUI IDE");
    println!("  init         Initialize a new project");
    println!("  lsp          Start the language server");
    println!("  new          Create a new project");
    println!("  publish      Publish the crate to crates.io");
    println!("  run          Run the project");
    println!("  test         Run the tests");
    println!("  upgrade      Upgrade the naux CLI");
    println!("  verify       Check, test, build, and benchmark the project");
    println!();
    println!("Examples:");
    println!("  naux run <file.nx>");
    println!("  naux dev ir <file.nx>");
    println!("  naux dev ssa-stats <file.nx> --iters 200");
    println!("  naux dev bench <file.nx> --engine vm --iters 100");
    println!("  naux dev benchrt <file.nx> --engine jit --trace-only");
    println!("  naux doctor --json --out target/naux-doctor.json");
    println!("  naux verify");
    Ok(())
}
