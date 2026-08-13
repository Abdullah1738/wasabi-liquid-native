#!/usr/bin/env python3
"""Mutation-test the private public-proof snapshot boundary."""

from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PREPARER = ROOT / "ci/prepare-ordinary-wallet-plan-proof-snapshot.py"
CHECKER = ROOT / "ci/check-ordinary-wallet-plan-public-proof-surface.py"


def explicit_source_cargo_home(arguments: list[str]) -> Path:
    if len(arguments) != 2:
        raise AssertionError(
            "usage: test-ordinary-wallet-plan-proof-snapshot.py ABSOLUTE_SOURCE_CARGO_HOME"
        )
    source_cargo_home = Path(arguments[1])
    if not source_cargo_home.is_absolute():
        raise AssertionError("absolute source Cargo home is required")
    metadata = os.lstat(source_cargo_home)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise AssertionError("source Cargo home must be an unlinked directory")
    return source_cargo_home


def test_source_cargo_home_argument(source_cargo_home: Path, scratch: Path) -> None:
    invalid_arguments = (
        ["test-ordinary-wallet-plan-proof-snapshot.py"],
        ["test-ordinary-wallet-plan-proof-snapshot.py", "relative-cargo-home"],
        [
            "test-ordinary-wallet-plan-proof-snapshot.py",
            str(source_cargo_home),
            "unexpected-extra-argument",
        ],
    )
    for arguments in invalid_arguments:
        try:
            explicit_source_cargo_home(arguments)
        except AssertionError:
            pass
        else:
            raise AssertionError(f"invalid source Cargo home arguments were accepted: {arguments!r}")

    linked_source_cargo_home = scratch / "linked-source-cargo-home"
    linked_source_cargo_home.symlink_to(source_cargo_home, target_is_directory=True)
    try:
        explicit_source_cargo_home(
            ["test-ordinary-wallet-plan-proof-snapshot.py", str(linked_source_cargo_home)]
        )
    except AssertionError:
        pass
    else:
        raise AssertionError("symlinked source Cargo home was accepted")


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"module import failed: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def copy_exact_inputs(preparer, destination: Path) -> None:
    for relative in preparer.FILES:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)


def expect_snapshot_rejected(preparer, source: Path, destination: Path) -> None:
    try:
        preparer.copy_exact_snapshot(source, destination)
    except preparer.SnapshotError:
        return
    raise AssertionError("invalid private proof snapshot input was accepted")


def expect_state_rejected(preparer, snapshot: Path, cargo_home: Path, authority: Path, authority_digest: str) -> None:
    try:
        preparer.verify_private_state(snapshot, cargo_home, authority, authority_digest)
    except preparer.SnapshotError:
        return
    raise AssertionError("mutated private proof state was accepted")


def expect_snapshot_error(preparer, operation, message: str) -> None:
    try:
        operation()
    except preparer.SnapshotError:
        return
    raise AssertionError(message)


def expect_snapshot_error_message(preparer, operation, expected: str) -> None:
    try:
        operation()
    except preparer.SnapshotError as error:
        if str(error) != expected:
            raise AssertionError(
                f"snapshot rejection differed: {str(error)!r} != {expected!r}"
            ) from error
        return
    raise AssertionError(f"snapshot operation unexpectedly succeeded: {expected}")


def archive_with_member(member: tarfile.TarInfo, data: bytes = b"") -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        root = tarfile.TarInfo("unsafe-1.0.0")
        root.type = tarfile.DIRTYPE
        root.mode = 0o755
        archive.addfile(root)
        if member.isfile():
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        else:
            archive.addfile(member)
    return output.getvalue()


def test_run_git_environment(preparer) -> None:
    original_run = preparer.subprocess.run
    calls = []

    def record_run(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return subprocess.CompletedProcess(arguments, 0, stdout=b"", stderr=b"")

    preparer.subprocess.run = record_run
    try:
        if preparer.run_git(Path("/usr/bin/git"), ["version"]) != b"":
            raise AssertionError("isolated Git command returned unexpected output")
    finally:
        preparer.subprocess.run = original_run
    if len(calls) != 1:
        raise AssertionError("isolated Git command was not singular")
    arguments, kwargs = calls[0]
    expected_environment = {
        "HOME": "/",
        "PATH": "/usr/bin:/bin",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "pack.writeReverseIndex",
        "GIT_CONFIG_VALUE_0": "false",
        "GIT_CONFIG_KEY_1": "maintenance.auto",
        "GIT_CONFIG_VALUE_1": "false",
        "GIT_TERMINAL_PROMPT": "0",
    }
    if (
        arguments != ["/usr/bin/git", "version"]
        or kwargs.get("cwd") != "/"
        or kwargs.get("env") != expected_environment
        or kwargs.get("stdin") != subprocess.DEVNULL
        or kwargs.get("stdout") != subprocess.PIPE
        or kwargs.get("stderr") != subprocess.PIPE
        or kwargs.get("check") is not False
    ):
        raise AssertionError("isolated Git command environment is not exact")


def test_archive_and_git_topology_rejections(preparer, scratch: Path) -> None:
    package = {"name": "unsafe", "version": "1.0.0"}
    unsafe_members = []
    symlink = tarfile.TarInfo("unsafe-1.0.0/symlink")
    symlink.type = tarfile.SYMTYPE
    symlink.linkname = "/tmp/escape"
    unsafe_members.append(("symlink", symlink))
    hardlink = tarfile.TarInfo("unsafe-1.0.0/hardlink")
    hardlink.type = tarfile.LNKTYPE
    hardlink.linkname = "unsafe-1.0.0/source"
    unsafe_members.append(("hardlink", hardlink))
    special = tarfile.TarInfo("unsafe-1.0.0/fifo")
    special.type = tarfile.FIFOTYPE
    unsafe_members.append(("special", special))
    traversal = tarfile.TarInfo("unsafe-1.0.0/../escape")
    traversal.type = tarfile.REGTYPE
    unsafe_members.append(("traversal", traversal))
    for name, member in unsafe_members:
        expect_snapshot_error(
            preparer,
            lambda member=member: preparer.registry_archive_entries(
                archive_with_member(member, b"body"), package
            ),
            f"registry archive {name} topology was accepted",
        )

    repository = scratch / "unsafe-git-tree"
    repository.mkdir()
    subprocess.run(["/usr/bin/git", "init", "-q", str(repository)], check=True)
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": "source test",
            "GIT_AUTHOR_EMAIL": "source-test@example.invalid",
            "GIT_COMMITTER_NAME": "source test",
            "GIT_COMMITTER_EMAIL": "source-test@example.invalid",
        }
    )
    (repository / "regular").write_bytes(b"regular")
    subprocess.run(["/usr/bin/git", "-C", str(repository), "add", "regular"], check=True)
    subprocess.run(
        ["/usr/bin/git", "-C", str(repository), "commit", "-q", "-m", "regular"],
        env=environment,
        check=True,
    )
    initial = subprocess.run(
        ["/usr/bin/git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    original_run_git = preparer.run_git
    head_output_limits: list[int] = []

    def record_git_output_limit(
        git_bin: Path,
        arguments: list[str],
        *,
        output_limit: int = preparer.MAX_SEALED_CACHE_TOTAL_BYTES,
    ) -> bytes:
        if arguments[-2:] == ["rev-parse", "HEAD"]:
            head_output_limits.append(output_limit)
        return original_run_git(git_bin, arguments, output_limit=output_limit)

    preparer.run_git = record_git_output_limit
    try:
        snapshot = scratch / "regular-git-workspace-snapshot"
        preparer.copy_git_workspace_snapshot(
            repository,
            snapshot,
            Path("/usr/bin/git"),
            initial,
        )
    finally:
        preparer.run_git = original_run_git
    if head_output_limits != [1024] or (snapshot / "regular").read_bytes() != b"regular":
        raise AssertionError("Git workspace head query was not bounded or copied exactly")

    os.symlink("regular", repository / "linked")
    subprocess.run(["/usr/bin/git", "-C", str(repository), "add", "linked"], check=True)
    subprocess.run(
        ["/usr/bin/git", "-C", str(repository), "commit", "-q", "-m", "linked"],
        env=environment,
        check=True,
    )
    linked_commit = subprocess.run(
        ["/usr/bin/git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    expect_snapshot_error(
        preparer,
        lambda: preparer.git_tree_files(Path("/usr/bin/git"), repository / ".git", linked_commit),
        "Git symlink entry was accepted",
    )
    (repository / "linked").unlink()
    subprocess.run(
        ["/usr/bin/git", "-C", str(repository), "update-index", "--force-remove", "linked"],
        check=True,
    )
    subprocess.run(
        [
            "/usr/bin/git",
            "-C",
            str(repository),
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{initial},submodule",
        ],
        check=True,
    )
    subprocess.run(
        ["/usr/bin/git", "-C", str(repository), "commit", "-q", "-m", "submodule"],
        env=environment,
        check=True,
    )
    submodule_commit = subprocess.run(
        ["/usr/bin/git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    expect_snapshot_error(
        preparer,
        lambda: preparer.git_tree_files(Path("/usr/bin/git"), repository / ".git", submodule_commit),
        "Git submodule entry was accepted",
    )


def cargo_binary() -> str:
    cargo = shutil.which("cargo")
    if cargo is None:
        raise AssertionError("Cargo is required for private proof snapshot mutations")
    return cargo


def materialize_sources(manifest: Path, cargo_home: Path, target: Path) -> None:
    environment = os.environ.copy()
    environment["CARGO_HOME"] = str(cargo_home)
    environment["CARGO_TARGET_DIR"] = str(target)
    result = subprocess.run(
        [
            cargo_binary(),
            "metadata",
            "--manifest-path",
            str(manifest),
            "--locked",
            "--offline",
            "--format-version",
            "1",
        ],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"Cargo source materialization failed: {result.stderr.decode()}")


def replace_sealed_file(path: Path, data: bytes) -> None:
    mode = path.stat().st_mode & 0o777
    os.chmod(path, mode | 0o200)
    try:
        path.write_bytes(data)
    finally:
        os.chmod(path, mode)


def add_sealed_file(parent: Path, name: str, data: bytes) -> Path:
    mode = parent.stat().st_mode & 0o777
    os.chmod(parent, mode | 0o200)
    target = parent / name
    try:
        target.write_bytes(data)
        os.chmod(target, 0o400)
    finally:
        os.chmod(parent, mode)
    return target


def mutate_sparse_locked_record(path: Path, version: str, mutation) -> None:
    data = path.read_bytes()
    fields = data[5:].split(b"\0")
    trailing = bool(fields and fields[-1] == b"")
    if trailing:
        fields.pop()
    matches = 0
    for index in range(1, len(fields), 2):
        if fields[index].decode("utf-8") == version:
            record = json.loads(fields[index + 1])
            mutation(record)
            fields[index + 1] = json.dumps(record, separators=(",", ":")).encode("utf-8")
            matches += 1
    if matches != 1:
        raise AssertionError("locked sparse record mutation target is not singular")
    path.write_bytes(data[:5] + b"\0".join(fields) + (b"\0" if trailing else b""))


def main() -> int:
    source_cargo_home = explicit_source_cargo_home(sys.argv)
    preparer = load(PREPARER, "proof_snapshot_preparer")
    checker = load(CHECKER, "proof_snapshot_surface")
    with tempfile.TemporaryDirectory(prefix="wlpq-proof-snapshot-") as directory:
        scratch = Path(directory)
        test_source_cargo_home_argument(source_cargo_home, scratch)
        test_run_git_environment(preparer)
        test_archive_and_git_topology_rejections(preparer, scratch)
        source = scratch / "source"
        copy_exact_inputs(preparer, source)

        cargo_home = scratch / "source-cargo-home"
        lock_bytes = (source / "ci/ordinary-wallet-plan-public-proof.Cargo.lock").read_bytes()
        preparer.copy_safe_cargo_cache(source_cargo_home, cargo_home, lock_bytes)
        selected_cache = preparer.exact_cache_sources(source_cargo_home, lock_bytes)
        workspace_lock_bytes = (ROOT / "Cargo.lock").read_bytes()
        workspace_cache = preparer.exact_cache_sources(source_cargo_home, workspace_lock_bytes)
        if len(selected_cache) >= len(workspace_cache):
            raise AssertionError("minimal proof cache authority includes workspace-only sources")
        cache_files = {relative: (cargo_home / relative).read_bytes() for relative in selected_cache}

        snapshot = scratch / "snapshot"
        materialized_cargo_home = scratch / "materialized-cargo-home"
        private_cargo_home = scratch / "private-cargo-home"
        preparer.copy_exact_snapshot(source, snapshot)
        preparer.copy_safe_cargo_cache(cargo_home, materialized_cargo_home, lock_bytes)
        materialize_sources(
            snapshot / "Cargo.toml",
            materialized_cargo_home,
            scratch / "materialize-target",
        )
        materialized_registry_file = next(
            path for path in sorted(materialized_cargo_home.glob("registry/src/**/*")) if path.is_file()
        )
        materialized_git_file = next(
            path
            for path in sorted(materialized_cargo_home.glob("git/checkouts/**/*"))
            if path.is_file() and ".git" not in path.relative_to(materialized_cargo_home).parts
        )
        for name, source_path in (
            ("registry", materialized_registry_file),
            ("git", materialized_git_file),
        ):
            mutated_materialization = scratch / f"mutated-{name}-materialization"
            shutil.copytree(materialized_cargo_home, mutated_materialization)
            mutated = mutated_materialization / source_path.relative_to(materialized_cargo_home)
            mutated.write_bytes(mutated.read_bytes() + b"between-materialization-and-seal")
            try:
                preparer.finalize_cache_state(
                    cargo_home,
                    mutated_materialization,
                    scratch / f"rejected-{name}-final",
                    scratch / f"rejected-{name}-authority",
                    lock_bytes,
                    Path("/usr/bin/git"),
                )
            except preparer.SnapshotError:
                pass
            else:
                raise AssertionError(f"{name} source mutation before final sealing was accepted")

        configured_git_materialization = scratch / "configured-git-materialization"
        shutil.copytree(materialized_cargo_home, configured_git_materialization)
        checkout_config = next(
            configured_git_materialization.glob("git/checkouts/*/*/.git/config")
        )
        with checkout_config.open("a", encoding="utf-8") as stream:
            stream.write('[core]\nhooksPath = "/tmp/unreviewed-hooks"\n')
        expect_snapshot_error(
            preparer,
            lambda: preparer.finalize_cache_state(
                cargo_home,
                configured_git_materialization,
                scratch / "rejected-configured-git-final",
                scratch / "rejected-configured-git-authority",
                lock_bytes,
                Path("/usr/bin/git"),
            ),
            "Git checkout configuration mutation before sealing was accepted",
        )

        checkout_git = next(
            materialized_cargo_home.glob("git/checkouts/*/*/.git")
        )
        checkout = checkout_git.parent
        database_name = checkout.parent.name
        database = materialized_cargo_home / "git/db" / database_name
        commit = next(
            pinned_commit
            for pinned_database, pinned_commit in preparer.GIT_DATABASES.values()
            if pinned_database == database_name
        )
        checkout_description = checkout_git / "description"
        os.chmod(checkout_description, 0o600)
        try:
            expect_snapshot_error_message(
                preparer,
                lambda: preparer.validate_checkout_git_metadata(
                    checkout, database, commit
                ),
                "Git checkout private metadata mode differs from exact authority: "
                "path_utf8_hex=6465736372697074696f6e is 0o600, expected 0o644",
            )
        finally:
            os.chmod(checkout_description, 0o644)

        unsafe_hook_relative = Path(
            "hooks/line\n::error title=spoofed::message\x1b.sample"
        )
        unsafe_hook = checkout_git / unsafe_hook_relative
        unsafe_hook.write_bytes(b"untrusted diagnostic path")
        os.chmod(unsafe_hook, 0o600)
        try:
            expect_snapshot_error_message(
                preparer,
                lambda: preparer.validate_checkout_git_metadata(
                    checkout, database, commit
                ),
                "Git checkout private metadata mode differs from exact authority: "
                f"path_utf8_hex={unsafe_hook_relative.as_posix().encode('utf-8').hex()} "
                "is 0o600, expected 0o755",
            )
        finally:
            unsafe_hook.unlink()

        for name, source_path in (
            ("registry", materialized_registry_file),
            ("git", materialized_git_file),
        ):
            hardlinked_materialization = scratch / f"hardlinked-{name}-materialization"
            shutil.copytree(materialized_cargo_home, hardlinked_materialization)
            hardlinked = hardlinked_materialization / source_path.relative_to(materialized_cargo_home)
            original = hardlinked.read_bytes()
            external = scratch / f"hardlink-{name}-mutation-target"
            external.write_bytes(original)
            hardlinked.unlink()
            os.link(external, hardlinked)
            external.write_bytes(b"transient")
            external.write_bytes(original)
            expect_snapshot_error(
                preparer,
                lambda: preparer.finalize_cache_state(
                    cargo_home,
                    hardlinked_materialization,
                    scratch / f"rejected-hardlink-{name}-final",
                    scratch / f"rejected-hardlink-{name}-authority",
                    lock_bytes,
                    Path("/usr/bin/git"),
                ),
                f"restored transient {name} hardlink mutation before sealing was accepted",
            )

        authority = scratch / "private-cargo-authority.jsonl"
        authority_digest = preparer.finalize_cache_state(
            cargo_home,
            materialized_cargo_home,
            private_cargo_home,
            authority,
            lock_bytes,
            Path("/usr/bin/git"),
        )
        preparer.normalize_read_only(snapshot)
        preparer.verify_private_state(snapshot, private_cargo_home, authority, authority_digest)
        materialize_sources(
            snapshot / "Cargo.toml",
            private_cargo_home,
            scratch / "final-cache-metadata-target",
        )
        for directory, _, files in os.walk(private_cargo_home):
            for name in files:
                if os.lstat(Path(directory) / name).st_nlink != 1:
                    raise AssertionError("final Cargo source closure retained a hardlink")
        authority_alias = scratch / "hardlinked-private-cargo-authority.jsonl"
        os.link(authority, authority_alias)
        expect_state_rejected(
            preparer,
            snapshot,
            private_cargo_home,
            authority,
            authority_digest,
        )
        authority_alias.unlink()
        preparer.verify_private_state(snapshot, private_cargo_home, authority, authority_digest)

        race_home = scratch / "race-source-cargo-home"
        shutil.copytree(cargo_home, race_home)
        race_relative = next(
            relative
            for relative in selected_cache
            if relative.is_relative_to("registry/index") and ".cache" in relative.parts
        )
        original_selector = preparer.exact_cache_sources
        selector_calls = 0

        def mutate_after_selection(source_root: Path, selected_lock: bytes):
            nonlocal selector_calls
            selected = original_selector(source_root, selected_lock)
            selector_calls += 1
            if selector_calls == 1:
                path = source_root / race_relative
                path.write_bytes(path.read_bytes() + b"changed-after-validation")
            return selected

        preparer.exact_cache_sources = mutate_after_selection
        try:
            preparer.copy_safe_cargo_cache(
                race_home, scratch / "race-private-cargo-home", lock_bytes
            )
        except preparer.SnapshotError:
            pass
        else:
            raise AssertionError("Cargo cache validation/copy race was accepted")
        finally:
            preparer.exact_cache_sources = original_selector

        configured_cache = scratch / "configured-private-cargo-home"
        shutil.copytree(private_cargo_home, configured_cache)
        add_sealed_file(
            configured_cache,
            "config.toml",
            b'[build]\nrustc-wrapper = "/not/reviewed"\n',
        )
        expect_state_rejected(preparer, snapshot, configured_cache, authority, authority_digest)

        dep_info = scratch / "proof.d"
        dep_info.write_text(
            "target: tools/ordinary-wallet-plan-public-proof-verifier/src/main.rs\n\n"
            "tools/ordinary-wallet-plan-public-proof-verifier/src/main.rs:\n",
            encoding="utf-8",
        )
        checker.run_snapshot(snapshot.absolute(), dep_info.absolute())

        for name, relative in (
            ("lock", Path("Cargo.lock")),
            ("case-table", preparer.VECTORS / "PUBLIC_PROOF_CASES_V1.tsv"),
            ("fixture", preparer.VECTORS / "public/main-candidate-valid.hex"),
            ("explicit-fixture", preparer.VECTORS / "public/test-candidate-explicit.hex"),
            ("unowned-fixture", preparer.VECTORS / "public/test-candidate-unowned.hex"),
            ("inventory", preparer.SNAPSHOT_INVENTORY),
        ):
            mutated_snapshot = scratch / f"mutated-{name}-snapshot"
            shutil.copytree(snapshot, mutated_snapshot)
            path = mutated_snapshot / relative
            os.chmod(path, 0o600)
            path.write_bytes(path.read_bytes() + b"x")
            try:
                checker.run_snapshot(mutated_snapshot.absolute(), dep_info.absolute())
            except checker.SurfaceError:
                pass
            else:
                raise AssertionError(f"private proof snapshot {name} mutation was accepted")

        extra_snapshot = scratch / "extra-snapshot"
        shutil.copytree(snapshot, extra_snapshot)
        os.chmod(extra_snapshot, 0o700)
        (extra_snapshot / "extra").write_bytes(b"extra")
        expect_state_rejected(preparer, extra_snapshot, private_cargo_home, authority, authority_digest)

        source_main = source / preparer.TOOL / "src/main.rs"
        snapshot_main = snapshot / preparer.TOOL / "src/main.rs"
        captured_main = snapshot_main.read_bytes()
        source_main.write_bytes(source_main.read_bytes() + b"// live mutation\n")
        if snapshot_main.read_bytes() != captured_main:
            raise AssertionError("live source mutation changed the private proof snapshot")
        checker.run_snapshot(snapshot.absolute(), dep_info.absolute())

        os.chmod(snapshot_main, 0o600)
        snapshot_main.write_bytes(snapshot_main.read_bytes() + b"// snapshot mutation\n")
        try:
            checker.run_snapshot(snapshot.absolute(), dep_info.absolute())
        except checker.SurfaceError:
            pass
        else:
            raise AssertionError("private proof snapshot byte mutation was accepted")
        replace_sealed_file(snapshot_main, captured_main)

        for relative, data in cache_files.items():
            source_path = cargo_home / relative
            copied_path = private_cargo_home / relative
            source_path.write_bytes(data + b" changed")
            if copied_path.read_bytes() != data:
                raise AssertionError("live Cargo cache mutation changed its private copy")
            source_path.write_bytes(data)
        if not (private_cargo_home / "registry/src").exists() or not (
            private_cargo_home / "git/checkouts"
        ).exists():
            raise AssertionError("sealed extracted Cargo source closure is incomplete")

        mutated_cache = scratch / "mutated-private-cargo-home"
        shutil.copytree(private_cargo_home, mutated_cache)
        copied_path = mutated_cache / next(iter(cache_files))
        replace_sealed_file(copied_path, copied_path.read_bytes() + b"changed")
        expect_state_rejected(preparer, snapshot, mutated_cache, authority, authority_digest)

        extra_cache = scratch / "extra-private-cargo-home"
        shutil.copytree(private_cargo_home, extra_cache)
        add_sealed_file(extra_cache / "registry/cache", "extra", b"extra")
        expect_state_rejected(preparer, snapshot, extra_cache, authority, authority_digest)

        empty_authority = scratch / "empty-cache-authority.jsonl"
        empty_authority.write_bytes(b"")
        expect_state_rejected(
            preparer,
            snapshot,
            private_cargo_home,
            empty_authority,
            hashlib.sha256(b"").hexdigest(),
        )

        reclosed_cache = scratch / "reclosed-private-cargo-home"
        shutil.copytree(private_cargo_home, reclosed_cache)
        archive = next(path for path in (reclosed_cache / "registry/cache").rglob("*.crate"))
        replace_sealed_file(archive, archive.read_bytes() + b"reclosed")
        add_sealed_file(
            reclosed_cache,
            "CACHE_SHA256SUMS",
            f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.relative_to(reclosed_cache).as_posix()}\n".encode(),
        )
        expect_state_rejected(preparer, snapshot, reclosed_cache, authority, authority_digest)

        source_file = next(
            path
            for path in sorted(private_cargo_home.glob("registry/src/**/*"))
            if path.is_file()
        )
        source_relative = source_file.relative_to(private_cargo_home)

        added_source_cache = scratch / "added-source-private-cargo-home"
        shutil.copytree(private_cargo_home, added_source_cache)
        add_sealed_file(
            (added_source_cache / source_relative).parent,
            "unreviewed-source",
            b"unreviewed",
        )
        expect_state_rejected(preparer, snapshot, added_source_cache, authority, authority_digest)

        modified_source_cache = scratch / "modified-source-private-cargo-home"
        shutil.copytree(private_cargo_home, modified_source_cache)
        modified_source = modified_source_cache / source_relative
        replace_sealed_file(modified_source, modified_source.read_bytes() + b"modified")
        expect_state_rejected(preparer, snapshot, modified_source_cache, authority, authority_digest)

        writable_root_cache = scratch / "writable-root-private-cargo-home"
        shutil.copytree(private_cargo_home, writable_root_cache)
        os.chmod(writable_root_cache, 0o700)
        expect_state_rejected(preparer, snapshot, writable_root_cache, authority, authority_digest)

        linked_source_cache = scratch / "linked-source-private-cargo-home"
        shutil.copytree(private_cargo_home, linked_source_cache)
        linked_parent = (linked_source_cache / source_relative).parent
        linked_parent_mode = linked_parent.stat().st_mode & 0o777
        os.chmod(linked_parent, linked_parent_mode | 0o200)
        try:
            os.symlink(linked_source_cache / source_relative, linked_parent / "linked-source")
        finally:
            os.chmod(linked_parent, linked_parent_mode)
        expect_state_rejected(preparer, snapshot, linked_source_cache, authority, authority_digest)

        special_source_cache = scratch / "special-source-private-cargo-home"
        shutil.copytree(private_cargo_home, special_source_cache)
        special_parent = (special_source_cache / source_relative).parent
        special_parent_mode = special_parent.stat().st_mode & 0o777
        os.chmod(special_parent, special_parent_mode | 0o200)
        try:
            os.mkfifo(special_parent / "special-source", 0o400)
        finally:
            os.chmod(special_parent, special_parent_mode)
        expect_state_rejected(preparer, snapshot, special_source_cache, authority, authority_digest)

        build_script_cache = scratch / "build-script-private-cargo-home"
        shutil.copytree(private_cargo_home, build_script_cache)
        build_script_target = build_script_cache / source_relative
        original_build_script_target = build_script_target.read_bytes()
        build_script_crate = scratch / "cache-mutation-build-script"
        build_script_crate.mkdir()
        (build_script_crate / "Cargo.toml").write_text(
            '[package]\nname = "cache-mutation-build-script"\nversion = "0.0.0"\nedition = "2024"\nbuild = "build.rs"\n',
            encoding="utf-8",
        )
        (build_script_crate / "build.rs").write_text(
            "use std::{env, fs};\n"
            "fn main() {\n"
            "    let path = env::var_os(\"SEALED_SOURCE_TARGET\").unwrap();\n"
            "    let mut permissions = fs::metadata(&path).unwrap().permissions();\n"
            "    permissions.set_readonly(false);\n"
            "    fs::set_permissions(&path, permissions).unwrap();\n"
            "    fs::write(path, b\"build-script-mutation\").unwrap();\n"
            "}\n",
            encoding="utf-8",
        )
        (build_script_crate / "src").mkdir()
        (build_script_crate / "src/lib.rs").write_text("", encoding="utf-8")
        build_environment = os.environ.copy()
        build_environment["CARGO_HOME"] = str(scratch / "build-script-runtime-cargo-home")
        build_environment["CARGO_TARGET_DIR"] = str(scratch / "build-script-target")
        build_environment["SEALED_SOURCE_TARGET"] = str(build_script_target)
        build_result = subprocess.run(
            [
                cargo_binary(),
                "build",
                "--manifest-path",
                str(build_script_crate / "Cargo.toml"),
                "--offline",
            ],
            env=build_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
        if build_result.returncode != 0 or build_script_target.read_bytes() == original_build_script_target:
            raise AssertionError(f"cache-mutating build script did not execute: {build_result.stderr.decode()}")
        expect_state_rejected(preparer, snapshot, build_script_cache, authority, authority_digest)

        original_sealed_file_count = preparer.MAX_SEALED_CACHE_FILES
        preparer.MAX_SEALED_CACHE_FILES = 0
        try:
            expect_state_rejected(
                preparer,
                snapshot,
                private_cargo_home,
                authority,
                authority_digest,
            )
        finally:
            preparer.MAX_SEALED_CACHE_FILES = original_sealed_file_count

        original_file_count = preparer.MAX_CACHE_FILES
        preparer.MAX_CACHE_FILES = 0
        try:
            preparer.copy_safe_cargo_cache(
                cargo_home, scratch / "file-count-cargo-home", lock_bytes
            )
        except preparer.SnapshotError:
            pass
        else:
            raise AssertionError("Cargo cache file-count bound was not enforced")
        finally:
            preparer.MAX_CACHE_FILES = original_file_count

        original_total = preparer.MAX_CACHE_TOTAL_BYTES
        preparer.MAX_CACHE_TOTAL_BYTES = 0
        try:
            preparer.copy_safe_cargo_cache(
                cargo_home, scratch / "aggregate-cargo-home", lock_bytes
            )
        except preparer.SnapshotError:
            pass
        else:
            raise AssertionError("Cargo cache aggregate byte bound was not enforced")
        finally:
            preparer.MAX_CACHE_TOTAL_BYTES = original_total

        changed_source = scratch / "changed-source"
        copy_exact_inputs(preparer, changed_source)
        changed = changed_source / preparer.TOOL / "src/main.rs"
        changed.write_bytes(changed.read_bytes() + b"// changed\n")
        expect_snapshot_rejected(preparer, changed_source, scratch / "changed-snapshot")

        linked_source = scratch / "linked-source"
        copy_exact_inputs(preparer, linked_source)
        linked = linked_source / preparer.TOOL / "src/main.rs"
        target = linked.with_name("main-target.rs")
        linked.rename(target)
        os.symlink(target, linked)
        expect_snapshot_rejected(preparer, linked_source, scratch / "linked-snapshot")

        linked_cargo_home = scratch / "linked-cargo-home"
        shutil.copytree(cargo_home, linked_cargo_home)
        first_relative = next(iter(selected_cache))
        linked = linked_cargo_home / first_relative
        linked_target = linked.with_name(linked.name + "-target")
        linked.rename(linked_target)
        os.symlink(linked_target, linked)
        try:
            preparer.copy_safe_cargo_cache(
                linked_cargo_home, scratch / "linked-private-cargo-home", lock_bytes
            )
        except preparer.SnapshotError:
            pass
        else:
            raise AssertionError("linked Cargo cache layer was accepted")

        changed_index_home = scratch / "changed-index-home"
        shutil.copytree(cargo_home, changed_index_home)
        index_entry = next(
            relative for relative in selected_cache if relative.is_relative_to("registry/index") and ".cache" in relative.parts
        )
        with (changed_index_home / index_entry).open("ab") as stream:
            stream.write(b"changed")
        try:
            preparer.copy_safe_cargo_cache(
                changed_index_home, scratch / "changed-index-private", lock_bytes
            )
        except preparer.SnapshotError:
            pass
        else:
            raise AssertionError("mutated sparse registry authority was accepted")

        bitcoin_index = next(
            relative
            for relative in selected_cache
            if relative.is_relative_to("registry/index")
            and relative.parts[-3:] == ("bi", "tc", "bitcoin")
        )
        sparse_mutations = {
            "deps": lambda record: record.__setitem__("deps", []),
            "features": lambda record: record.__setitem__("features", {"unreviewed": []}),
            "features2": lambda record: record.__setitem__("features2", {"unreviewed": []}),
            "target": lambda record: record["deps"][0].__setitem__("target", "cfg(unix)"),
            "links": lambda record: record.__setitem__("links", "unreviewed"),
        }
        for name, mutation in sparse_mutations.items():
            mutated_index_home = scratch / f"mutated-index-{name}-home"
            shutil.copytree(cargo_home, mutated_index_home)
            mutate_sparse_locked_record(
                mutated_index_home / bitcoin_index,
                "0.32.102",
                mutation,
            )
            try:
                preparer.copy_safe_cargo_cache(
                    mutated_index_home,
                    scratch / f"mutated-index-{name}-private",
                    lock_bytes,
                )
            except preparer.SnapshotError:
                pass
            else:
                raise AssertionError(f"mutated sparse registry {name} authority was accepted")

        git_object = next(
            path.relative_to(cargo_home)
            for path in sorted((cargo_home / "git/db").glob("*/objects/**/*"))
            if path.is_file()
        )
        objects_index = git_object.parts.index("objects")
        git_objects = Path(*git_object.parts[: objects_index + 1])

        reverse_index_home = scratch / "reverse-index-git-home"
        shutil.copytree(cargo_home, reverse_index_home)
        source_pack = next(
            path for path in sorted((cargo_home / "git/db").glob("*/objects/pack/*.pack"))
        )
        generated_pack = scratch / "reverse-index-generator" / source_pack.name
        generated_pack.parent.mkdir()
        shutil.copy2(source_pack, generated_pack)
        generated = subprocess.run(
            ["/usr/bin/git", "index-pack", "--rev-index", str(generated_pack)],
            cwd="/",
            env={
                "HOME": "/",
                "PATH": "/usr/bin:/bin",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_SYSTEM": "/dev/null",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "pack.writeReverseIndex",
                "GIT_CONFIG_VALUE_0": "true",
                "GIT_TERMINAL_PROMPT": "0",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        generated_reverse_index = generated_pack.with_suffix(".rev")
        if generated.returncode != 0 or not generated_reverse_index.is_file():
            raise AssertionError(
                "failed to construct valid Git reverse-index mutation: "
                + generated.stderr.decode("utf-8", errors="replace")
            )
        source_objects = source_pack.parent.parent
        reverse_index = (
            reverse_index_home
            / source_objects.relative_to(cargo_home)
            / "pack"
            / generated_reverse_index.name
        )
        shutil.copy2(generated_reverse_index, reverse_index)
        reverse_relative = reverse_index.relative_to(
            reverse_index_home / source_objects.relative_to(cargo_home)
        ).as_posix()
        try:
            preparer.exact_cache_sources(reverse_index_home, lock_bytes)
        except preparer.SnapshotError as error:
            expected = (
                "Git object database contains an unreviewed pack sidecar: "
                f"{reverse_relative!r}"
            )
            if str(error) != expected:
                raise AssertionError(
                    "Git reverse-index rejection did not identify its exact relative path: "
                    f"{error}"
                ) from error
        else:
            raise AssertionError("valid Git reverse-index sidecar was accepted")

        commit_graph_home = scratch / "commit-graph-git-home"
        shutil.copytree(cargo_home, commit_graph_home)
        graph_id = "0" * 40
        commit_graph_directory = (
            commit_graph_home
            / source_objects.relative_to(cargo_home)
            / "info/commit-graphs"
        )
        commit_graph_directory.mkdir(parents=True)
        (commit_graph_directory / "commit-graph-chain").write_text(
            graph_id + "\n", encoding="ascii"
        )
        (commit_graph_directory / f"graph-{graph_id}.graph").write_bytes(b"CGPH")
        try:
            preparer.exact_cache_sources(commit_graph_home, lock_bytes)
        except preparer.SnapshotError as error:
            expected = (
                "Git object database contains unreviewed indirection or metadata: "
                "'info/commit-graphs/commit-graph-chain'"
            )
            if str(error) != expected:
                raise AssertionError(
                    "Git commit-graph rejection did not identify its exact relative path: "
                    f"{error}"
                ) from error
        else:
            raise AssertionError("Git commit-graph metadata was accepted")

        alternate_home = scratch / "alternate-git-home"
        shutil.copytree(cargo_home, alternate_home)
        alternates = alternate_home / git_objects / "info/alternates"
        alternates.parent.mkdir(parents=True, exist_ok=True)
        alternates.write_text("/tmp/unreviewed-object-db\n", encoding="utf-8")
        try:
            preparer.copy_safe_cargo_cache(
                alternate_home, scratch / "alternate-private-cargo-home", lock_bytes
            )
        except preparer.SnapshotError:
            pass
        else:
            raise AssertionError("external Git object indirection was accepted")

        configured_git_home = scratch / "configured-git-home"
        shutil.copytree(cargo_home, configured_git_home)
        git_database = configured_git_home / git_objects.parent
        with (git_database / "config").open("a", encoding="utf-8") as stream:
            stream.write('[core]\nhooksPath = "/tmp/unreviewed-hooks"\n')
        try:
            preparer.exact_cache_sources(configured_git_home, lock_bytes)
        except preparer.SnapshotError:
            pass
        else:
            raise AssertionError("unreviewed Git configuration was accepted")

        promisor_home = scratch / "promisor-git-home"
        shutil.copytree(cargo_home, promisor_home)
        promisor = promisor_home / git_objects / ("pack/pack-" + "0" * 40 + ".promisor")
        promisor.parent.mkdir(parents=True, exist_ok=True)
        promisor.write_bytes(b"promisor")
        try:
            preparer.exact_cache_sources(promisor_home, lock_bytes)
        except preparer.SnapshotError:
            pass
        else:
            raise AssertionError("promisor Git object authority was accepted")

        broad_index_home = scratch / "broad-index-home"
        shutil.copytree(cargo_home, broad_index_home)
        registry_index = broad_index_home / "registry/index"
        for index in range(preparer.MAX_CACHE_ENTRIES + 1):
            (registry_index / f"unreviewed-{index:04d}").mkdir()
        try:
            preparer.exact_cache_sources(broad_index_home, lock_bytes)
        except preparer.SnapshotError:
            pass
        else:
            raise AssertionError("unbounded registry index topology was accepted")

        broad_git_home = scratch / "broad-git-home"
        shutil.copytree(cargo_home, broad_git_home)
        git_objects_root = broad_git_home / git_objects
        for index in range(preparer.MAX_CACHE_ENTRIES + 1):
            (git_objects_root / f"unreviewed-{index:04d}").mkdir()
        try:
            preparer.exact_cache_sources(broad_git_home, lock_bytes)
        except preparer.SnapshotError:
            pass
        else:
            raise AssertionError("unbounded Git object topology was accepted")

    print("ordinary-wallet-plan private proof snapshot mutations accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
