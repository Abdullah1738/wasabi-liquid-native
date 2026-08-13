#!/usr/bin/env python3
"""Create the exact build script used to prove the isolated compiler boundary."""

from __future__ import annotations

import os
import sys
from pathlib import Path


MANIFEST = b'''[package]
name = "sealed-build-boundary-probe"
version = "0.0.0"
edition = "2024"
build = "build.rs"
'''

BUILD = r'''use std::{
    env, fs, io,
    net::{SocketAddr, TcpStream},
    process::{Command, Stdio},
    time::Duration,
};

fn require_denied_write(name: &str) {
    let path = env::var_os(name).expect("sealed target path");
    let metadata = fs::metadata(&path).expect("sealed target metadata");
    let mut permissions = metadata.permissions();
    permissions.set_readonly(false);
    let permission_changed = fs::set_permissions(&path, permissions).is_ok();
    let write_path = if metadata.is_dir() {
        std::path::Path::new(&path).join("sealed-denied-write-probe")
    } else {
        std::path::PathBuf::from(&path)
    };
    let wrote = fs::write(&write_path, b"boundary escape").is_ok();
    if wrote {
        let _ = fs::remove_file(&write_path);
    }
    if permission_changed || wrote {
        panic!("sealed source mutation was permitted: {name}");
    }
}

fn require_hidden_home() {
    let path = env::var_os("SEALED_ORIGINAL_CARGO_HOME").expect("original Cargo home path");
    match fs::metadata(path) {
        Ok(_) => panic!("original home remained readable inside build boundary"),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) => {}
        Err(error) => panic!("original home denial was not OS-enforced: {error}"),
    }
}

fn require_allowed_write(name: &str) {
    let root = env::var_os(name).expect("allowed build root");
    let path = std::path::Path::new(&root).join("sealed-write-probe");
    fs::write(&path, name.as_bytes()).expect("exact build-owned root must be writable");
    fs::remove_file(path).expect("allowed write probe cleanup");
}

fn spawn_delayed_writer() {
    let target = env::var_os("SEALED_DELAYED_WRITE_TARGET").expect("delayed writer target");
    Command::new("/bin/sh")
        .args(["-c", "sleep 5; printf escaped > \"$1\"", "wlpq-delayed-writer"])
        .arg(target)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("delayed descendant probe");
}

fn main() {
    let sudo = Command::new("/usr/bin/sudo")
        .args(["-n", "true"])
        .status()
        .expect("absolute sudo probe");
    assert!(!sudo.success(), "build identity unexpectedly has sudo authority");
    require_denied_write("SEALED_DEPENDENCY_TARGET");
    require_denied_write("SEALED_WORKSPACE_TARGET");
    require_denied_write("SEALED_HOST_WRITE_TARGET");
    require_denied_write("SEALED_VAR_TMP_TARGET");
    require_denied_write("SEALED_INACTIVE_BUILD_TARGET");
    require_hidden_home();
    require_allowed_write("SEALED_BUILD_HOME");
    require_allowed_write("SEALED_BUILD_TMP");
    require_allowed_write("SEALED_BUILD_TARGET");
    for (name, _) in env::vars_os() {
        let name = name.to_string_lossy().to_ascii_uppercase();
        assert!(
            !name.contains("TOKEN")
                && !name.contains("SECRET")
                && !name.starts_with("AWS_")
                && !name.starts_with("GITHUB_"),
            "credential-like environment entered build boundary"
        );
    }
    let destination: SocketAddr = "1.1.1.1:443".parse().unwrap();
    match TcpStream::connect_timeout(&destination, Duration::from_secs(1)) {
        Ok(_) => panic!("direct network connection escaped build boundary"),
        Err(error) if matches!(error.kind(), io::ErrorKind::PermissionDenied | io::ErrorKind::NetworkUnreachable) => {}
        Err(error) => panic!("network denial was not OS-enforced: {error}"),
    }
    spawn_delayed_writer();
}
'''.encode()
LOCK = b'''version = 4

[[package]]
name = "sealed-build-boundary-probe"
version = "0.0.0"
'''


def write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, data)
    finally:
        os.close(descriptor)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: prepare-sealed-build-boundary-probe.py ABSOLUTE_DESTINATION", file=sys.stderr)
        return 2
    destination = Path(sys.argv[1])
    if not destination.is_absolute() or os.path.lexists(destination):
        print("sealed build boundary probe requires a fresh absolute destination", file=sys.stderr)
        return 1
    destination.mkdir(mode=0o700, parents=True)
    write_new(destination / "Cargo.toml", MANIFEST)
    write_new(destination / "Cargo.lock", LOCK)
    write_new(destination / "build.rs", BUILD)
    write_new(destination / "src/lib.rs", b"")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
