#!/usr/bin/env python3
"""Mutation-test the pre-Cargo workspace fetch authority."""

from __future__ import annotations

import importlib.util
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
CHECKER = Path(__file__).with_name("check-cargo-fetch-preflight.py")


def rejected(operation, message: str) -> None:
    try:
        operation()
    except (OSError, ValueError):
        return
    raise AssertionError(message)


def read_during_mutation(checker, root: Path, relative: Path, mutation) -> bytes:
    original_read = checker.os.read
    mutated = False

    def mutating_read(descriptor: int, count: int) -> bytes:
        nonlocal mutated
        data = original_read(descriptor, count)
        if not mutated:
            mutated = True
            mutation()
        return data

    with mock.patch.object(checker.os, "read", mutating_read):
        return checker.read_regular(root, relative)


def read_after_preopen_mutation(checker, root: Path, relative: Path, mutation) -> bytes:
    original_open = checker.os.open
    mutated = False

    def mutating_open(path, flags, *args, **kwargs):
        nonlocal mutated
        if not mutated:
            mutated = True
            mutation()
        return original_open(path, flags, *args, **kwargs)

    with mock.patch.object(checker.os, "open", mutating_open):
        return checker.read_regular(root, relative)


def main() -> int:
    spec = importlib.util.spec_from_file_location("fetch_preflight", CHECKER)
    if spec is None or spec.loader is None:
        raise AssertionError("fetch preflight checker import failed")
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    checker.validate(ROOT)
    with tempfile.TemporaryDirectory(prefix="wlpq-fetch-preflight-") as directory:
        test_root = Path(directory).resolve()
        (test_root / "ci").mkdir()
        for relative in (Path("Cargo.toml"), Path("Cargo.lock"), Path("ci/ordinary-wallet-plan-public-proof.Cargo.lock")):
            (test_root / relative).write_bytes((ROOT / relative).read_bytes())
        checker.validate(test_root)

        lock = test_root / "Cargo.lock"
        original_lock = lock.read_bytes()
        lock.write_bytes(bytes([original_lock[0] ^ 1]) + original_lock[1:])
        rejected(lambda: checker.validate(test_root), "Cargo lock content mutation was accepted")
        lock.write_bytes(original_lock)

        read_root = test_root / "read-mutations"
        read_root.mkdir()
        relative = Path("authority")
        authority = read_root / relative
        authority_data = b"stable fetch authority\n"

        authority.write_bytes(b"")
        if checker.read_regular(read_root, relative, maximum=0) != b"":
            raise AssertionError("empty fetch authority was not read exactly")
        authority.write_bytes(authority_data)
        if checker.read_regular(read_root, relative, maximum=len(authority_data)) != authority_data:
            raise AssertionError("exact-maximum fetch authority was not read exactly")
        rejected(
            lambda: checker.read_regular(read_root, relative, maximum=len(authority_data) - 1),
            "maximum-plus-one fetch authority was accepted",
        )

        linked = read_root / "linked-authority"
        os.link(authority, linked)
        rejected(
            lambda: checker.read_regular(read_root, relative),
            "hardlinked fetch authority was accepted",
        )
        linked.unlink()

        symlink = read_root / "symlink-authority"
        symlink.symlink_to(authority)
        rejected(
            lambda: checker.read_regular(read_root, symlink.relative_to(read_root)),
            "symlinked fetch authority was accepted",
        )

        directory_authority = read_root / "directory-authority"
        directory_authority.mkdir()
        rejected(
            lambda: checker.read_regular(read_root, directory_authority.relative_to(read_root)),
            "nonregular fetch authority was accepted",
        )

        fifo_authority = read_root / "fifo-authority"
        os.mkfifo(fifo_authority)
        with mock.patch.object(
            checker.os,
            "open",
            side_effect=AssertionError("nonregular authority reached open"),
        ):
            rejected(
                lambda: checker.read_regular(read_root, fifo_authority.relative_to(read_root)),
                "FIFO fetch authority was accepted",
            )

        authority.write_bytes(authority_data)
        initial = os.lstat(authority)
        atime_only = SimpleNamespace(
            st_dev=initial.st_dev,
            st_ino=initial.st_ino,
            st_mode=initial.st_mode,
            st_nlink=initial.st_nlink,
            st_size=initial.st_size,
            st_atime_ns=initial.st_atime_ns + 1_000_000_000,
            st_mtime_ns=initial.st_mtime_ns,
            st_ctime_ns=initial.st_ctime_ns,
        )
        with mock.patch.object(checker.os, "lstat", side_effect=[initial, atime_only]):
            accepted = checker.read_regular(read_root, relative)
        if accepted != authority_data:
            raise AssertionError("atime-only drift changed accepted fetch preflight bytes")

        authority.write_bytes(authority_data)
        initial = os.lstat(authority)

        def mutate_content() -> None:
            with authority.open("r+b", buffering=0) as stream:
                stream.write(bytes([authority_data[0] ^ 1]))
            os.utime(
                authority,
                ns=(initial.st_atime_ns, initial.st_mtime_ns + 1_000_000_000),
                follow_symlinks=False,
            )

        rejected(
            lambda: read_during_mutation(checker, read_root, relative, mutate_content),
            "content mutation during fetch preflight read was accepted",
        )

        authority.write_bytes(authority_data)
        initial = os.lstat(authority)

        def mutate_content_and_restore_mtime() -> None:
            with authority.open("r+b", buffering=0) as stream:
                stream.write(bytes([authority_data[0] ^ 1]))
            os.utime(
                authority,
                ns=(initial.st_atime_ns, initial.st_mtime_ns),
                follow_symlinks=False,
            )
            if os.lstat(authority).st_ctime_ns == initial.st_ctime_ns:
                raise AssertionError("same-size rewrite did not produce a testable ctime change")

        rejected(
            lambda: read_during_mutation(
                checker,
                read_root,
                relative,
                mutate_content_and_restore_mtime,
            ),
            "same-size content mutation with restored mtime was accepted",
        )

        authority.write_bytes(authority_data)

        def grow_authority() -> None:
            with authority.open("ab", buffering=0) as stream:
                stream.write(b"growth")

        rejected(
            lambda: read_during_mutation(
                checker,
                read_root,
                relative,
                grow_authority,
            ),
            "size mutation during fetch preflight read was accepted",
        )

        authority.write_bytes(authority_data)

        def truncate_authority() -> None:
            with authority.open("r+b", buffering=0) as stream:
                stream.truncate(1)

        rejected(
            lambda: read_during_mutation(checker, read_root, relative, truncate_authority),
            "truncation during fetch preflight read was accepted",
        )

        authority.write_bytes(authority_data)
        replacement = read_root / "replacement"

        def replace_inode() -> None:
            replacement.write_bytes(authority_data)
            os.replace(replacement, authority)

        rejected(
            lambda: read_during_mutation(checker, read_root, relative, replace_inode),
            "inode mutation during fetch preflight read was accepted",
        )

        authority.write_bytes(authority_data)
        preopen_replacement = read_root / "preopen-replacement"

        def replace_inode_before_open() -> None:
            preopen_replacement.write_bytes(authority_data)
            os.replace(preopen_replacement, authority)

        rejected(
            lambda: read_after_preopen_mutation(
                checker,
                read_root,
                relative,
                replace_inode_before_open,
            ),
            "inode mutation between fetch preflight lstat and open was accepted",
        )

        authority.write_bytes(authority_data)
        initial_mode = os.lstat(authority).st_mode & 0o777

        def mutate_mode() -> None:
            os.chmod(authority, initial_mode ^ 0o100)

        rejected(
            lambda: read_during_mutation(
                checker,
                read_root,
                relative,
                mutate_mode,
            ),
            "mode mutation during fetch preflight read was accepted",
        )
        os.chmod(authority, initial_mode)

        authority.write_bytes(authority_data)
        initial = os.lstat(authority)
        rejected(
            lambda: read_during_mutation(
                checker,
                read_root,
                relative,
                lambda: os.utime(
                    authority,
                    ns=(initial.st_atime_ns, initial.st_mtime_ns + 1_000_000_000),
                    follow_symlinks=False,
                ),
            ),
            "mtime mutation during fetch preflight read was accepted",
        )

        cargo_config = test_root / ".cargo/config.toml"
        cargo_config.parent.mkdir()
        cargo_config.write_text('[registry]\nglobal-credential-providers = ["cargo:token"]\n', encoding="utf-8")
        rejected(lambda: checker.validate(test_root), "workspace Cargo credential provider was accepted")
        configuration_root = test_root / "configuration-root"
        (configuration_root / ".cargo").mkdir(parents=True)
        (configuration_root / ".cargo/config.toml").write_text("[net]\noffline = true\n", encoding="utf-8")
        rejected(
            lambda: checker.validate_configuration_root(configuration_root),
            "Cargo configuration above the fetch manifest was accepted",
        )
    print("Cargo fetch preflight mutations accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
