//! Rust Audit fixture: deliberately bad code on purpose. DO NOT FIX.
//!
//! Every construct below maps to a rule in the catalog of `scripts/rust_audit.py`
//! and is asserted by `tests/test_rust_audit.py`:
//!   R01/R03 `compute`  · R02 `test_ok`  · R09 `load`  · R10 `parse_config`
//!   R12 `connect` (assignment shape the safe fix can rewrite)  ·  R18b in
//!   `src/legacy.rs` (not part of the module tree, so `cargo test` stays green
//!   while the scanner still reads the file).

pub fn compute(x: i32) -> i32 {
    todo!()
}

pub fn parse_config(s: &str) -> Result<i32, std::num::ParseIntError> {
    let _ = s.trim();
    s.parse::<i32>()
}

pub fn load() -> String {
    std::fs::read_to_string("config.toml").unwrap()
}

pub fn connect() {
    let api_key = "AKIAIOSFODNN7EXAMPLE";
    drop(api_key);
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_ok() {
        assert!(true);
    }
}
