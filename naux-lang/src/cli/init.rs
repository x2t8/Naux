use std::fs;
use std::path::Path;

/// Scaffold a new NAUX project at `path` (default: current dir).
#[allow(dead_code)]
pub fn init_project(path: &str) {
    let dir = Path::new(path);

    if dir.exists()
        && dir
            .read_dir()
            .map(|mut d| d.next().is_some())
            .unwrap_or(false)
    {
        eprintln!("error: path `{}` exists and is not empty", path);
        return;
    }

    if let Err(e) = fs::create_dir_all(dir) {
        eprintln!("error: failed to create `{}`: {}", path, e);
        return;
    }

    let main_content = r#"~ rite
    !say "Hello from NAUX project!"
~ end
"#;
    if let Err(e) = fs::write(dir.join("main.nx"), main_content) {
        eprintln!("error: failed to write main.nx: {}", e);
        return;
    }

    let readme_content = r#"# NAUX Project

Small NAUX project scaffolded by `naux init`.

## Run
```bash
naux run main.nx --mode=cli
```

## License
Add your preferred license before publishing.
"#;
    if let Err(e) = fs::write(dir.join("README.md"), readme_content) {
        eprintln!("error: failed to write README.md: {}", e);
        return;
    }

    let gitignore_content = "target\n.naux\n";
    let _ = fs::write(dir.join(".gitignore"), gitignore_content);

    let license_content = r#"MIT License

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
    let _ = fs::write(dir.join("LICENSE"), license_content);

    let toml_content = r#"[project]
name = "naux-project"
version = "0.1.0"
authors = ["Author"]

[build]
entry = "main.nx"
mode = "cli"
engine = "vm"
output = "build"
"#;
    let _ = fs::write(dir.join("naux.toml"), toml_content);

    println!("Project created at `{}`", path);
}