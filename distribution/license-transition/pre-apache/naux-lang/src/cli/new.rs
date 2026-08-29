use std::fs;
use std::path::Path;

const MAIN_SOURCE: &str = r#"~ rite
    !say "Welcome to NAUX!"
    !say "Summoned from the 48 DNA."
~ end
"#;

const BENCH_SOURCE: &str = r#"~ rite
    $n = 1000
    $i = 0
    $sum = 0
    ~ while $i < $n
        $sum = $sum + $i
        $i = $i + 1
    ~ end
    ^ $sum
~ end
"#;

const TEST_SOURCE: &str = r#"~ rite
    $actual = 2 + 2
    ~ if $actual != 4
        !log "[FAIL] arithmetic smoke"
    ~ end
    ^ $actual
~ end
"#;

const LICENSE: &str = r#"MIT License

Copyright (c) 2026 Author

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"#;

pub fn handle_new(name: String) -> Result<(), String> {
    let root = Path::new(&name);
    if root.exists() {
        return Err(format!("Thư mục `{name}` đã tồn tại"));
    }
    scaffold_project(root)?;
    println!("Đã tạo project NAUX tại `{name}`");
    Ok(())
}

pub(crate) fn scaffold_project(root: &Path) -> Result<(), String> {
    fs::create_dir_all(root.join("src")).map_err(|err| format!("Không tạo được src/: {err}"))?;
    fs::create_dir_all(root.join("tests"))
        .map_err(|err| format!("Không tạo được tests/: {err}"))?;
    write(root.join("main.nx"), MAIN_SOURCE)?;
    write(root.join("bench.nx"), BENCH_SOURCE)?;
    write(root.join("tests").join("smoke_test.nx"), TEST_SOURCE)?;
    write(root.join(".gitignore"), "build/\ntarget/\n.naux/\n")?;
    write(
        root.join("README.md"),
        "# Naux Project\n\nRun the complete local workflow with:\n\n```bash\nnaux verify\n```\n",
    )?;
    write(root.join("LICENSE"), LICENSE)?;

    let project_name = root
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("naux-app");
    let manifest = format!(
        r#"[project]
name = "{project_name}"
version = "0.1.0"

[run]
engine = "vm"
mode = "cli"

[build]
entry = "main.nx"
mode = "cli"
engine = "vm"
output = "build"

[verify]
benchmark = "bench.nx"
engine = "vm"
iters = 5
warmup_ms = 0
"#
    );
    write(root.join("naux.toml"), &manifest)
}

fn write(path: impl AsRef<Path>, content: &str) -> Result<(), String> {
    let path = path.as_ref();
    fs::write(path, content).map_err(|err| format!("Không ghi {}: {err}", path.display()))
}
