#!/usr/bin/env python3
"""Mutation-test the CI-only public-proof verifier source boundary."""

from __future__ import annotations

import importlib.util
import os
import shutil
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "ci/check-ordinary-wallet-plan-public-proof-surface.py"
TOOL = Path("tools/ordinary-wallet-plan-public-proof-verifier")
MAIN = TOOL / "src/main.rs"


def load_checker():
    spec = importlib.util.spec_from_file_location("proof_surface", CHECKER)
    if spec is None or spec.loader is None:
        raise AssertionError("proof surface checker import failed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def copy_root(scratch: Path, name: str) -> tuple[Path, Path]:
    target = scratch / name
    (target / TOOL.parent).mkdir(parents=True)
    shutil.copy2(ROOT / "Cargo.toml", target / "Cargo.toml")
    shutil.copytree(ROOT / TOOL, target / TOOL)
    dep_info = target / "proof.d"
    dep_info.write_text(
        "target: tools/ordinary-wallet-plan-public-proof-verifier/src/main.rs\n\n"
        "tools/ordinary-wallet-plan-public-proof-verifier/src/main.rs:\n",
        encoding="utf-8",
    )
    return target, dep_info


def expect_rejected(checker, scratch: Path, name: str, action) -> None:
    root, dep_info = copy_root(scratch, name)
    action(root, dep_info)
    try:
        checker.run(root.absolute(), dep_info.absolute())
    except checker.SurfaceError:
        return
    raise AssertionError(f"public proof surface mutation was accepted: {name}")


def main() -> int:
    checker = load_checker()
    with tempfile.TemporaryDirectory(prefix="wlpq-proof-surface-") as directory:
        scratch = Path(directory)
        valid, valid_dep_info = copy_root(scratch, "valid")
        checker.run(valid.absolute(), valid_dep_info.absolute())

        expect_rejected(
            checker,
            scratch,
            "workspace-reentry",
            lambda root, _: (root / "Cargo.toml").write_text(
                (root / "Cargo.toml").read_text(encoding="utf-8").replace(
                    'exclude = ["tools/ordinary-wallet-plan-public-proof-verifier"]\n',
                    "",
                    1,
                ),
                encoding="utf-8",
            ),
        )

        def add_module(root: Path, dep_info: Path) -> None:
            (root / TOOL / "src/helper.rs").write_text("pub fn escape() {}\n", encoding="utf-8")
            path = root / MAIN
            path.write_text("mod helper;\n" + path.read_text(encoding="utf-8"), encoding="utf-8")
            dep_info.write_text(
                dep_info.read_text(encoding="utf-8").replace(
                    "src/main.rs\n", "src/main.rs tools/ordinary-wallet-plan-public-proof-verifier/src/helper.rs\n", 1
                ),
                encoding="utf-8",
            )

        expect_rejected(checker, scratch, "module", add_module)

        def add_include(root: Path, dep_info: Path) -> None:
            extra = root / TOOL / "src/extra.bin"
            extra.write_bytes(b"extra")
            path = root / MAIN
            path.write_text(
                'const EXTRA: &[u8] = include_bytes!("extra.bin");\n' + path.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            dep_info.write_text(
                dep_info.read_text(encoding="utf-8").replace(
                    "src/main.rs\n", "src/main.rs tools/ordinary-wallet-plan-public-proof-verifier/src/extra.bin\n", 1
                ),
                encoding="utf-8",
            )

        expect_rejected(checker, scratch, "include-bytes", add_include)
        expect_rejected(
            checker,
            scratch,
            "repository-cargo-config",
            lambda root, _: (
                (root / ".cargo").mkdir(),
                (root / ".cargo/config.toml").write_text(
                    '[build]\nrustc-wrapper = "/definitely/not-reviewed"\n',
                    encoding="utf-8",
                ),
            ),
        )

        def external_dep_info(_: Path, dep_info: Path) -> None:
            dep_info.write_text(
                dep_info.read_text(encoding="utf-8").replace(
                    "src/main.rs\n",
                    "src/main.rs /tmp/hidden-compiled.rs\n",
                    1,
                ),
                encoding="utf-8",
            )

        expect_rejected(checker, scratch, "external-dep-info", external_dep_info)
        expect_rejected(
            checker,
            scratch,
            "production-suffix",
            lambda root, _: (root / MAIN).write_text(
                (root / MAIN).read_text(encoding="utf-8")
                + 'fn escaped_production_suffix() { std::process::Command::new("true"); }\n',
                encoding="utf-8",
            ),
        )
        expect_rejected(
            checker,
            scratch,
            "filesystem-alias",
            lambda root, _: (root / MAIN).write_text(
                (root / MAIN).read_text(encoding="utf-8").replace(
                    "use std::env;\n",
                    "use std::env;\nuse std::fs as hidden;\n",
                    1,
                ).replace(
                    "\n#[cfg(test)]\nmod tests {",
                    "\nfn hidden_write() { let _ = hidden::write(\"sentinel\", b\"x\"); }\n\n#[cfg(test)]\nmod tests {",
                    1,
                ),
                encoding="utf-8",
            ),
        )
        expect_rejected(
            checker,
            scratch,
            "command-alias",
            lambda root, _: (root / MAIN).write_text(
                (root / MAIN).read_text(encoding="utf-8").replace(
                    "use std::env;\n",
                    "use std::env;\nuse std::process::Command as Hidden;\n",
                    1,
                ).replace(
                    "\n#[cfg(test)]\nmod tests {",
                    "\nfn hidden_command() { let _ = Hidden::new(\"true\"); }\n\n#[cfg(test)]\nmod tests {",
                    1,
                ),
                encoding="utf-8",
            ),
        )
        expect_rejected(
            checker,
            scratch,
            "unsafe-ffi",
            lambda root, _: (root / MAIN).write_text(
                (root / MAIN).read_text(encoding="utf-8").replace(
                    "\n#[cfg(test)]\nmod tests {",
                    '\nunsafe extern "C" { fn system(command: *const i8) -> i32; }\n\n#[cfg(test)]\nmod tests {',
                    1,
                ),
                encoding="utf-8",
            ),
        )
        expect_rejected(
            checker,
            scratch,
            "build-script",
            lambda root, _: (root / TOOL / "Cargo.toml").write_text(
                (root / TOOL / "Cargo.toml").read_text(encoding="utf-8").replace(
                    "build = false\n", 'build = "build.rs"\n', 1
                ),
                encoding="utf-8",
            ),
        )
        if hasattr(os, "symlink"):
            def replace_with_symlink(root: Path, _: Path) -> None:
                source = root / MAIN
                target = root / TOOL / "source-target.rs"
                source.rename(target)
                os.symlink(target, source)

            expect_rejected(checker, scratch, "symlink", replace_with_symlink)

            def replace_tool_with_symlink(root: Path, _: Path) -> None:
                tool = root / TOOL
                target = root / "proof-tool-target"
                tool.rename(target)
                os.symlink(target, tool)

            expect_rejected(checker, scratch, "tool-directory-symlink", replace_tool_with_symlink)

            def replace_root_with_symlink(root: Path, _: Path) -> None:
                target = root.with_name(f"{root.name}-target")
                root.rename(target)
                os.symlink(target, root)

            expect_rejected(checker, scratch, "repository-root-symlink", replace_root_with_symlink)

    print("ordinary-wallet-plan public proof surface mutations accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
