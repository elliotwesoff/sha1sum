use std::process::Command;
use tempfile::NamedTempFile;
use std::io::Write;

#[test]
fn sha1_e2e_test() {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(b"hello world").unwrap();

    let sys = Command::new("sha1sum")
        .arg(f.path())
        .output()
        .unwrap();

    let sys_hash = String::from_utf8(sys.stdout).unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();

    let ours = Command::new(env!("CARGO_BIN_EXE_sha1sum"))
        .arg("1")
        .arg(f.path())
        .output()
        .unwrap();

    let ours_hash = String::from_utf8(ours.stdout).unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();

    assert_eq!(sys_hash, ours_hash);
}

