use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Input .nx file
    #[arg(short, long)]
    file: Option<String>,

    /// Output mode: json|cli|html
    #[arg(short, long, default_value = "json")]
    mode: String,
}

fn main() {
    let args = Args::parse();
    // TODO: wire parser + runtime + renderer using args.file and args.mode
    println!("TODO: NAUX CLI stub. file={:?}, mode={}", args.file, args.mode);
}
