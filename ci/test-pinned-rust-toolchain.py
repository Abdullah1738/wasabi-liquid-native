#!/usr/bin/env python3
"""Mutation-test the complete pinned Rust component file authority."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import tempfile
from pathlib import Path


CHECKER = Path(__file__).with_name("check-pinned-rust-toolchain.py")


def expect_rejected(operation, message: str) -> None:
    try:
        operation()
    except (OSError, ValueError):
        return
    raise AssertionError(message)


def main() -> int:
    spec = importlib.util.spec_from_file_location("pinned_toolchain", CHECKER)
    if spec is None or spec.loader is None:
        raise AssertionError("pinned toolchain checker import failed")
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    targets = {"aarch64-apple-darwin", "x86_64-unknown-linux-gnu"}
    executables = {
        "cargo",
        "rustc",
        "rustdoc",
        "rustfmt",
        "cargo-fmt",
        "cargo-clippy",
        "clippy-driver",
    }
    if (
        set(checker.EXPECTED) != targets
        or set(checker.COMPONENTS) != targets
        or set(checker.NON_MANIFEST_FILES) != targets
    ):
        raise AssertionError("pinned Rust target authority is incomplete")
    for target in targets:
        if set(checker.EXPECTED[target]) != executables:
            raise AssertionError(f"pinned Rust executable authority is incomplete: {target}")
        suffix = f"-{target}"
        component_prefixes = {"cargo", "rustc", "rust-std", "rustfmt-preview", "clippy-preview"}
        if {name.removesuffix(suffix) for name in checker.COMPONENTS[target]} != component_prefixes:
            raise AssertionError(f"pinned Rust component authority is incomplete: {target}")
        for relative, expected_source, expected_sealed in (
            (Path("bin/cargo"), 0o755, 0o555),
            (Path("lib/rustlib") / target / "bin/rust-lld", 0o755, 0o555),
            (Path("lib/rustlib") / target / "lib/libcore-reviewed.rlib", 0o644, 0o444),
            (Path("share/doc/rust/README.md"), 0o644, 0o444),
        ):
            if (
                checker.reviewed_mode(relative, target, sealed=False) != expected_source
                or checker.reviewed_mode(relative, target, sealed=True) != expected_sealed
            ):
                raise AssertionError(f"pinned Rust source/sealed mode policy differs: {target}:{relative}")
    with tempfile.TemporaryDirectory(prefix="wlpq-toolchain-") as directory:
        root = Path(directory).resolve() / "toolchain"
        rustlib = root / "lib/rustlib"
        rustlib.mkdir(parents=True)
        component = "fixture-host"
        (rustlib / "components").write_text(component + "\n", encoding="utf-8")
        relative = Path("lib/compiler-runtime.dylib")
        runtime = root / relative
        runtime.parent.mkdir(exist_ok=True)
        runtime.write_bytes(b"reviewed compiler runtime")
        executable_relative = Path("bin/compiler")
        executable = root / executable_relative
        executable.parent.mkdir()
        executable.write_bytes(b"reviewed compiler executable")
        executable.chmod(0o755)
        manifest_paths = (relative, executable_relative)
        manifest = b"".join(f"file:{path.as_posix()}\n".encode() for path in manifest_paths)
        manifest_path = rustlib / f"manifest-{component}"
        manifest_path.write_bytes(manifest)
        aggregate_hash = hashlib.sha256()
        for path in manifest_paths:
            aggregate_hash.update(
                path.as_posix().encode()
                + b"\0"
                + hashlib.sha256((root / path).read_bytes()).hexdigest().encode()
                + b"\n"
            )
        aggregate = aggregate_hash.hexdigest()
        checker.COMPONENTS["fixture"] = {
            component: (len(manifest), hashlib.sha256(manifest).hexdigest(), aggregate)
        }
        installer_version = rustlib / "rust-installer-version"
        installer_version.write_bytes(b"3")
        checker.NON_MANIFEST_FILES["fixture"] = {
            "lib/rustlib/rust-installer-version": (1, hashlib.sha256(b"3").hexdigest())
        }
        checker.EXPECTED["fixture"] = {"compiler": hashlib.sha256(executable.read_bytes()).hexdigest()}
        checker.validate_toolchain(root, "fixture")

        runtime.write_bytes(b"mutated compiler runtime")
        expect_rejected(
            lambda: checker.validate_toolchain(root, "fixture"),
            "mutated compiler runtime was accepted",
        )
        runtime.write_bytes(b"reviewed compiler runtime")

        manifest_path.write_bytes(manifest + b"file:extra\n")
        expect_rejected(
            lambda: checker.validate_toolchain(root, "fixture"),
            "mutated component manifest was accepted",
        )
        manifest_path.write_bytes(manifest)

        (rustlib / "components").write_text("unreviewed\n", encoding="utf-8")
        expect_rejected(
            lambda: checker.validate_toolchain(root, "fixture"),
            "missing component membership was accepted",
        )
        (rustlib / "components").write_text(component + "\n", encoding="utf-8")

        executable.write_bytes(b"mutated compiler executable")
        expect_rejected(
            lambda: checker.validate_toolchain(root, "fixture"),
            "mutated compiler executable was accepted",
        )
        executable.write_bytes(b"reviewed compiler executable")

        installer_version.write_bytes(b"4")
        expect_rejected(
            lambda: checker.validate_toolchain(root, "fixture"),
            "mutated non-manifest sysroot file was accepted",
        )
        installer_version.write_bytes(b"3")

        hardlink_target = root / "lib/compiler-runtime-hardlink.dylib"
        runtime.rename(hardlink_target)
        os.link(hardlink_target, runtime)
        expect_rejected(
            lambda: checker.validate_toolchain(root, "fixture"),
            "hardlinked compiler runtime was accepted",
        )
        runtime.unlink()
        hardlink_target.rename(runtime)

        copied = Path(directory).resolve() / "copied-toolchain"
        shutil.copytree(root, copied, copy_function=shutil.copy2)
        checker.validate_toolchain(copied, "fixture")
        (copied / "lib/rustlib/rust-installer-version").write_bytes(b"copy-race")
        expect_rejected(
            lambda: checker.validate_toolchain(copied, "fixture"),
            "toolchain copy-boundary mutation was accepted",
        )

        raced = Path(directory).resolve() / "raced-toolchain"
        race_fired = False

        def racing_copy(source, destination, *, follow_symlinks=True):
            nonlocal race_fired
            source_path = Path(source)
            if source_path == runtime and not race_fired:
                source_path.write_bytes(b"copy-boundary race")
                race_fired = True
            return shutil.copy2(source, destination, follow_symlinks=follow_symlinks)

        shutil.copytree(root, raced, copy_function=racing_copy)
        if not race_fired:
            raise AssertionError("toolchain copy-boundary race did not activate")
        expect_rejected(
            lambda: checker.validate_toolchain(raced, "fixture"),
            "toolchain copy-boundary race was accepted",
        )
        runtime.write_bytes(b"reviewed compiler runtime")

        constructed = Path(directory).resolve() / "constructed-toolchain"
        checker.construct_toolchain(root, constructed, "fixture")
        checker.validate_toolchain(constructed, "fixture", sealed=True)

        constructed.chmod(0o755)
        extra_directory = constructed / "unreviewed-empty-directory"
        extra_directory.mkdir(mode=0o555)
        constructed.chmod(0o555)
        expect_rejected(
            lambda: checker.validate_toolchain(constructed, "fixture", sealed=True),
            "extra sealed toolchain directory was accepted",
        )
        constructed.chmod(0o755)
        extra_directory.rmdir()

        constructed.chmod(0o755)
        extra_file = constructed / "unreviewed-file"
        extra_file.write_bytes(b"unreviewed")
        extra_file.chmod(0o444)
        constructed.chmod(0o555)
        expect_rejected(
            lambda: checker.validate_toolchain(constructed, "fixture", sealed=True),
            "extra sealed toolchain file was accepted",
        )
        constructed.chmod(0o755)
        extra_file.unlink()
        constructed.chmod(0o555)

        constructed.chmod(0o755)
        constructed_runtime = constructed / relative
        constructed_runtime.chmod(0o644)
        constructed.chmod(0o555)
        expect_rejected(
            lambda: checker.validate_toolchain(constructed, "fixture", sealed=True),
            "writable-style sealed toolchain file mode was accepted",
        )
        constructed_runtime.chmod(0o444)

        constructed.chmod(0o755)
        (constructed / "lib").chmod(0o755)
        constructed.chmod(0o555)
        expect_rejected(
            lambda: checker.validate_toolchain(constructed, "fixture", sealed=True),
            "writable-style sealed toolchain directory mode was accepted",
        )
        (constructed / "lib").chmod(0o555)

        components_path = constructed / "lib/rustlib/components"
        components_path.chmod(0o644)
        components_path.write_text(component + "\nunreviewed\n", encoding="utf-8")
        components_path.chmod(0o444)
        expect_rejected(
            lambda: checker.validate_toolchain(constructed, "fixture", sealed=True),
            "extra sealed toolchain component was accepted",
        )
        components_path.chmod(0o644)
        components_path.write_text(component + "\n", encoding="utf-8")
        components_path.chmod(0o444)

        constructed_manifest = constructed / "lib/rustlib" / f"manifest-{component}"
        constructed_manifest.chmod(0o644)
        constructed_manifest.write_bytes(manifest + b"file:extra\n")
        constructed_manifest.chmod(0o444)
        expect_rejected(
            lambda: checker.validate_toolchain(constructed, "fixture", sealed=True),
            "extra sealed toolchain manifest entry was accepted",
        )
        constructed_manifest.chmod(0o644)
        constructed_manifest.write_bytes(manifest)
        constructed_manifest.chmod(0o444)

        missing_runtime = constructed / relative
        missing_runtime.parent.chmod(0o755)
        missing_runtime.chmod(0o644)
        missing_runtime.unlink()
        expect_rejected(
            lambda: checker.validate_toolchain(constructed, "fixture", sealed=True),
            "missing sealed toolchain component file was accepted",
        )

        source_bad_mode = Path(directory).resolve() / "source-bad-mode"
        shutil.copytree(root, source_bad_mode, copy_function=shutil.copy2)
        (source_bad_mode / relative).chmod(0o600)
        expect_rejected(
            lambda: checker.construct_toolchain(
                source_bad_mode,
                Path(directory).resolve() / "bad-mode-construction",
                "fixture",
            ),
            "source component mode mismatch was accepted during construction",
        )

        runtime_target = root / "lib/compiler-runtime-target.dylib"
        runtime.rename(runtime_target)
        os.symlink(runtime_target.name, runtime)
        expect_rejected(
            lambda: checker.validate_toolchain(root, "fixture"),
            "linked compiler runtime was accepted",
        )
    print("pinned Rust toolchain mutations accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
