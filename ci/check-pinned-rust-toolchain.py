#!/usr/bin/env python3
"""Resolve the exact reviewed Rust 1.96 executable set without running it."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from pathlib import Path


EXPECTED = {
    "aarch64-apple-darwin": {
        "cargo": "fec239e6b74df873f54ef52912bfcfcc8d8414bc14a7ae1e0be80460bae72841",
        "rustc": "c5922366bfe3d6d028a65d626f4e629b3adad066995cf0b60c8a4b617bba5ffe",
        "rustdoc": "702eb65b0e89c984a8466468d41c0e82fb6db5396a5bdd47d25c053fc346287f",
        "rustfmt": "d3bf25e0aef37bbe0951090017f8c1f913cf5ac50e8108747c6e704c2ac1f8b9",
        "cargo-fmt": "a3626a1379846d575e4d495a57984b8be2971c3f9427fb6a3fa6ab74641f8a67",
        "cargo-clippy": "2619a7f4712053affe0efef165de75c7293fd759d834bc2c4a82de510919caef",
        "clippy-driver": "a1e69abcc2e4d7a27dc5083c673a47991add66c4aad5cf8b01fb0dd54c3fc791",
    },
    "x86_64-unknown-linux-gnu": {
        "cargo": "f30f9fd1b1d0b8fd10dc33219eb4cd4bec3543f40e434ac71f5a03fd0359063f",
        "rustc": "ba4b837efb6612dfa8d941c5a72b8a50d1d03a0f36216743b173949aa8d9eb75",
        "rustdoc": "ead78a0e00004d88ef7a3209a20552ba805cc9cb7cde7b061093a1b2dfb037c0",
        "rustfmt": "342c3d56e8958da0b108108a39e37ceac64ebdd42e6eefafa237d219e5b7eb0c",
        "cargo-fmt": "a4de43380ee9346aa1e336f3fede81cdba710dd6dee788c0a5fdd4baa85bec1d",
        "cargo-clippy": "dbadbd2a606ee9287460a5d287b7577a66bd304e7fe5570868e2a2eb4eed8fad",
        "clippy-driver": "a257170cec8a94b74792022936c574fc602330ce1c53b041074666f3f8977de2",
    },
}
COMPONENTS = {
    "aarch64-apple-darwin": {
        "cargo-aarch64-apple-darwin": (1532, "5b2160ec3635b8c8f3129f12cbeee078d55d882f9362313e56e9fd484febe8ba", "05c9bd00736c3f0220c119cdfa42bc0a567a3815bedb174ecfb00d385959b615"),
        "rustc-aarch64-apple-darwin": (1737, "9992a7bcf2246f3696deeb8febea1841a006502755631854d281a782e7aab9d0", "fb32320709f3f0cbffb3eb79cb6f71fbf275dfed99177a139e5e8ec6537adf65"),
        "rust-std-aarch64-apple-darwin": (4624, "39ab297e95a9c0a53ff26b9a986894ac96fae670b2c7f2c69936a31d981ab8a8", "513d288d4e7685f96f869f145397189a91a873dd00d5c712497e45413703fb73"),
        "rustfmt-preview-aarch64-apple-darwin": (142, "f131ba42a6667b5237b9fdca791e2da1fecd7b5cabf522b50efe5113aaaa60d7", "bed50e318590ef952eec9ce2012a629c0ae958361e9c8af56bc67faf90b1a03f"),
        "clippy-preview-aarch64-apple-darwin": (148, "266e3ebcb2cfa74930e774ac54d80e089f3d1ac299b085c7800114fc653502b9", "463e03ea35a621cde52baeee095d463f61bf6a69505c7c4c8c0714e07a835c4b"),
    },
    "x86_64-unknown-linux-gnu": {
        "cargo-x86_64-unknown-linux-gnu": (1532, "5b2160ec3635b8c8f3129f12cbeee078d55d882f9362313e56e9fd484febe8ba", "7324a41eec2e3ccfc8e9f6824da6a29846246cc3e44f3186b2c5dd216b6184b8"),
        "rustc-x86_64-unknown-linux-gnu": (1691, "a5a5a22bac0a93e4a63a6330e631d50eeb4acb1b26a4be52834dc5492364ad5d", "582f33340ec0aecd017ee5ed0f59aa89921c2d34fb99d3ecfafcc2618d062e12"),
        "rust-std-x86_64-unknown-linux-gnu": (5063, "5a4fc2b7850e950cb09ba0f8ff33cccfdaafd325143937f6cc9624e8f80ec6cd", "4e7905f6df6b9683444e18148ce85483f531bde9d7adae76b6226e9979489f5a"),
        "rustfmt-preview-x86_64-unknown-linux-gnu": (142, "f131ba42a6667b5237b9fdca791e2da1fecd7b5cabf522b50efe5113aaaa60d7", "93f7795be21542bf10c7f0b55ae5abac3a29455fb140558e187054af3f0ee8c6"),
        "clippy-preview-x86_64-unknown-linux-gnu": (148, "266e3ebcb2cfa74930e774ac54d80e089f3d1ac299b085c7800114fc653502b9", "0444b0e6140ff7f5296080b13cfcba573793ea8a7474fc26c504ab0441f08b9d"),
    },
}
NON_MANIFEST_FILES = {
    "aarch64-apple-darwin": {
        "lib/rustlib/rust-installer-version": (1, "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce"),
    },
    "x86_64-unknown-linux-gnu": {
        "lib/rustlib/rust-installer-version": (1, "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce"),
    },
}


def identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size, value.st_mtime_ns


def digest_regular(path: Path, expected_owner: int | None = None) -> str:
    for ancestor in path.parents:
        metadata = os.lstat(ancestor)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("pinned toolchain ancestry is linked or non-directory")
    before = os.lstat(path)
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or (expected_owner is not None and before.st_uid != expected_owner)
    ):
        raise ValueError("pinned toolchain file is linked, hardlinked, or nonregular")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if identity(before) != identity(opened):
            raise ValueError("pinned toolchain executable changed before open")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        if identity(opened) != identity(os.fstat(descriptor)) or identity(opened) != identity(os.lstat(path)):
            raise ValueError("pinned toolchain executable changed during read")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def read_small_regular(path: Path, expected_owner: int | None = None) -> bytes:
    for ancestor in path.parents:
        metadata = os.lstat(ancestor)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("pinned toolchain manifest ancestry is linked or non-directory")
    before = os.lstat(path)
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or (expected_owner is not None and before.st_uid != expected_owner)
        or before.st_size > 1024 * 1024
    ):
        raise ValueError("pinned toolchain manifest is linked, hardlinked, nonregular, or oversized")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        data = os.read(descriptor, 1024 * 1024 + 1)
        if identity(before) != identity(opened) or identity(opened) != identity(os.fstat(descriptor)) or identity(opened) != identity(os.lstat(path)) or len(data) != opened.st_size:
            raise ValueError("pinned toolchain manifest changed during read")
        return data
    finally:
        os.close(descriptor)


def host_target() -> str:
    system = os.uname()
    target = {
        ("Darwin", "arm64"): "aarch64-apple-darwin",
        ("Linux", "x86_64"): "x86_64-unknown-linux-gnu",
    }.get((system.sysname, system.machine))
    if target not in EXPECTED:
        raise ValueError("host has no reviewed Rust 1.96 executable authority")
    return target


def reviewed_mode(relative: Path, target: str, *, sealed: bool) -> int:
    target_bin = Path("lib/rustlib") / target / "bin"
    target_lib = Path("lib/rustlib") / target / "lib"
    executable = (
        relative.parent == Path("bin")
        or relative.parent == Path("libexec")
        or relative.is_relative_to(target_bin)
        or (
            relative.parent == target_lib
            and relative.name.startswith("libstd-")
            and relative.suffix in {".dylib", ".so"}
        )
    )
    if sealed:
        return 0o555 if executable else 0o444
    return 0o755 if executable else 0o644


def parse_component_manifest(data: bytes, component: str) -> list[Path]:
    paths: list[Path] = []
    seen: set[Path] = set()
    for line in data.decode("utf-8").splitlines():
        kind, separator, name = line.partition(":")
        relative = Path(name)
        if (
            kind != "file"
            or separator != ":"
            or relative.is_absolute()
            or ".." in relative.parts
            or relative.as_posix() != name
            or relative in seen
        ):
            raise ValueError(f"pinned Rust component manifest is noncanonical: {component}")
        seen.add(relative)
        paths.append(relative)
    return paths


def write_fresh(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while constructing pinned toolchain")
            view = view[written:]
    finally:
        os.close(descriptor)
    os.chmod(path, mode)


def copy_stable_regular(source_root: Path, destination_root: Path, relative: Path, target: str) -> str:
    source = source_root / relative
    before = os.lstat(source)
    expected_mode = reviewed_mode(relative, target, sealed=False)
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != expected_mode
    ):
        raise ValueError(f"pinned Rust component source mode or type mismatch: {relative}")
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    destination = destination_root / relative
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if identity(before) != identity(opened):
            raise ValueError(f"pinned Rust component changed before construction: {relative}")
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(output, view)
                if written <= 0:
                    raise OSError("short write while constructing pinned toolchain")
                view = view[written:]
        if identity(opened) != identity(os.fstat(descriptor)) or identity(opened) != identity(os.lstat(source)):
            raise ValueError(f"pinned Rust component changed during construction: {relative}")
    finally:
        os.close(output)
        os.close(descriptor)
    os.chmod(destination, reviewed_mode(relative, target, sealed=True))
    return digest.hexdigest()


def validate_components(
    root: Path,
    target: str,
    expected_owner: int | None = None,
    *,
    sealed: bool = False,
) -> set[Path]:
    rustlib = root / "lib/rustlib"
    installed_data = read_small_regular(rustlib / "components", expected_owner)
    installed = installed_data.decode("utf-8").splitlines()
    required = set(COMPONENTS[target])
    if (set(installed) != required if sealed else not required.issubset(installed)):
        raise ValueError("pinned Rust component set is incomplete")
    if sealed and installed_data != b"".join(component.encode("utf-8") + b"\n" for component in COMPONENTS[target]):
        raise ValueError("sealed Rust component membership is noncanonical")
    all_paths: set[Path] = set()
    for component, (manifest_length, manifest_digest, aggregate_digest) in COMPONENTS[target].items():
        manifest = rustlib / f"manifest-{component}"
        data = read_small_regular(manifest, expected_owner)
        if len(data) != manifest_length or hashlib.sha256(data).hexdigest() != manifest_digest:
            raise ValueError(f"pinned Rust component manifest mismatch: {component}")
        aggregate = hashlib.sha256()
        paths = parse_component_manifest(data, component)
        all_paths.update(paths)
        for relative in paths:
            mode = stat.S_IMODE(os.lstat(root / relative).st_mode)
            if mode != reviewed_mode(relative, target, sealed=sealed):
                raise ValueError(f"pinned Rust component mode mismatch: {relative}")
            digest = digest_regular(root / relative, expected_owner)
            aggregate.update(relative.as_posix().encode("utf-8") + b"\0" + digest.encode("ascii") + b"\n")
        if aggregate.hexdigest() != aggregate_digest:
            raise ValueError(f"pinned Rust component file inventory mismatch: {component}")
    return all_paths


def exact_regular_topology(root: Path, expected_owner: int | None = None) -> tuple[set[Path], set[Path]]:
    files: set[Path] = set()
    directory_paths: set[Path] = {Path(".")}
    def fail_traversal(error: OSError) -> None:
        raise error

    for directory, child_directories, names in os.walk(
        root,
        topdown=True,
        onerror=fail_traversal,
        followlinks=False,
    ):
        child_directories.sort()
        names.sort()
        for name in [*child_directories, *names]:
            metadata = os.lstat(Path(directory) / name)
            if stat.S_ISLNK(metadata.st_mode) or not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise ValueError("sealed Rust toolchain contains a linked or special entry")
            if expected_owner is not None and metadata.st_uid != expected_owner:
                raise ValueError("sealed Rust toolchain entry ownership differs")
        directory_paths.update((Path(directory) / name).relative_to(root) for name in child_directories)
        files.update((Path(directory) / name).relative_to(root) for name in names)
    return directory_paths, files


def validate_toolchain(
    root: Path,
    target: str,
    expected_owner: int | None = None,
    *,
    sealed: bool = False,
) -> None:
    root_metadata = os.lstat(root)
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode) or (
        expected_owner is not None and root_metadata.st_uid != expected_owner
    ):
        raise ValueError("pinned Rust toolchain root ownership or type mismatch")
    component_files = validate_components(root, target, expected_owner, sealed=sealed)
    for relative, (expected_length, expected_digest) in NON_MANIFEST_FILES[target].items():
        path = Path(relative)
        data = read_small_regular(root / path, expected_owner)
        if len(data) != expected_length or hashlib.sha256(data).hexdigest() != expected_digest:
            raise ValueError(f"pinned Rust non-manifest file mismatch: {relative}")
        if stat.S_IMODE(os.lstat(root / path).st_mode) != reviewed_mode(path, target, sealed=sealed):
            raise ValueError(f"pinned Rust non-manifest mode mismatch: {relative}")
    for executable, expected_digest in EXPECTED[target].items():
        if digest_regular(root / "bin" / executable, expected_owner) != expected_digest:
            raise ValueError(f"pinned Rust executable digest mismatch: {executable}")
    if sealed:
        metadata_files = {
            Path("lib/rustlib/components"),
            *(Path("lib/rustlib") / f"manifest-{component}" for component in COMPONENTS[target]),
            *(Path(relative) for relative in NON_MANIFEST_FILES[target]),
        }
        expected_files = component_files | metadata_files
        expected_directories = {Path(".")}
        for path in expected_files:
            expected_directories.update(parent for parent in path.parents if parent != Path("."))
        actual_directories, actual_files = exact_regular_topology(root, expected_owner)
        if actual_files != expected_files or actual_directories != expected_directories:
            raise ValueError("sealed Rust toolchain topology contains missing or extra files")
        for directory, directories, files in os.walk(root, topdown=True, onerror=lambda error: (_ for _ in ()).throw(error), followlinks=False):
            if stat.S_IMODE(os.lstat(directory).st_mode) != 0o555:
                raise ValueError("sealed Rust toolchain directory mode differs")
            for name in files:
                relative = (Path(directory) / name).relative_to(root)
                expected_mode = reviewed_mode(relative, target, sealed=True) if relative in component_files else 0o444
                if stat.S_IMODE(os.lstat(Path(directory) / name).st_mode) != expected_mode:
                    raise ValueError(f"sealed Rust toolchain file mode differs: {relative}")


def construct_toolchain(source: Path, destination: Path, target: str) -> None:
    if not source.is_absolute() or not destination.is_absolute() or os.path.lexists(destination):
        raise ValueError("absolute source and fresh destination are required")
    destination.mkdir(mode=0o700, parents=True)
    manifests: dict[str, tuple[bytes, list[Path], str]] = {}
    required_paths: set[Path] = set()
    for component, (length, digest, aggregate) in COMPONENTS[target].items():
        relative = Path("lib/rustlib") / f"manifest-{component}"
        data = read_small_regular(source / relative)
        if len(data) != length or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"pinned Rust component manifest mismatch: {component}")
        paths = parse_component_manifest(data, component)
        required_paths.update(paths)
        manifests[component] = data, paths, aggregate
    copied: dict[Path, str] = {}
    for relative in sorted(required_paths, key=lambda path: path.as_posix().encode("utf-8")):
        copied[relative] = copy_stable_regular(source, destination, relative, target)
    for component, (data, paths, expected_aggregate) in manifests.items():
        aggregate = hashlib.sha256()
        for relative in paths:
            aggregate.update(relative.as_posix().encode("utf-8") + b"\0" + copied[relative].encode("ascii") + b"\n")
        if aggregate.hexdigest() != expected_aggregate:
            raise ValueError(f"pinned Rust component changed during construction: {component}")
        write_fresh(destination / "lib/rustlib" / f"manifest-{component}", data, 0o444)
    components = b"".join(component.encode("utf-8") + b"\n" for component in COMPONENTS[target])
    write_fresh(destination / "lib/rustlib/components", components, 0o444)
    for relative_text, (length, digest) in NON_MANIFEST_FILES[target].items():
        relative = Path(relative_text)
        data = read_small_regular(source / relative)
        if len(data) != length or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"pinned Rust non-manifest file mismatch: {relative}")
        if stat.S_IMODE(os.lstat(source / relative).st_mode) != reviewed_mode(relative, target, sealed=False):
            raise ValueError(f"pinned Rust non-manifest mode mismatch: {relative}")
        write_fresh(destination / relative, data, 0o444)
    for directory, directories, files in os.walk(destination, topdown=False, followlinks=False):
        for name in directories:
            os.chmod(Path(directory) / name, 0o555)
    os.chmod(destination, 0o555)
    validate_toolchain(destination, target, sealed=True)


def main() -> int:
    if len(sys.argv) not in (2, 3, 4) or (
        len(sys.argv) == 3 and sys.argv[1] not in {"--toolchain-root", "--root-owned-toolchain"}
    ) or (
        len(sys.argv) == 4 and sys.argv[1] != "--construct-toolchain"
    ):
        print("usage: check-pinned-rust-toolchain.py ABSOLUTE_HOME | (--toolchain-root | --root-owned-toolchain) ABSOLUTE_ROOT | --construct-toolchain ABSOLUTE_SOURCE ABSOLUTE_DESTINATION", file=sys.stderr)
        return 2
    try:
        target = host_target()
        if len(sys.argv) == 4:
            source, destination = map(lambda value: Path(value).absolute(), sys.argv[2:])
            construct_toolchain(source, destination, target)
            print(destination)
            return 0
        supplied = Path(sys.argv[-1])
        if not supplied.is_absolute():
            raise ValueError("absolute toolchain authority path is required")
        root = supplied if len(sys.argv) == 3 else supplied / ".rustup/toolchains" / f"1.96.0-{target}"
        sealed = len(sys.argv) == 3
        validate_toolchain(
            root,
            target,
            0 if sys.argv[1:2] == ["--root-owned-toolchain"] else None,
            sealed=sealed,
        )
    except (OSError, ValueError) as error:
        print(f"pinned Rust toolchain check failed: {error}", file=sys.stderr)
        return 1
    print(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
