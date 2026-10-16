// Not wired into the module tree on purpose: `cargo test` never compiles this
// file, but Rust Audit scans it. R18b: `fs` is a std module, not a crate.
use fs::File;

pub fn open(path: &str) -> std::io::Result<File> {
    File::open(path)
}
