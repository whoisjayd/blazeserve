#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub fn blaze() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_blaze"));
    cmd.env_remove("BLAZE_LOG_JSON").env("NO_COLOR", "1");
    cmd
}

pub fn run(args: &[&str]) -> Output {
    blaze().args(args).output().expect("spawn blaze")
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

pub fn code(o: &Output) -> i32 {
    o.status.code().expect("process exited with a status code")
}

/// Incompressible-looking bytes, so truncation or reordering shows up in comparisons.
pub fn pattern(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

pub fn canonical(dir: &Path) -> PathBuf {
    std::fs::canonicalize(dir).expect("canonicalize temp dir")
}
