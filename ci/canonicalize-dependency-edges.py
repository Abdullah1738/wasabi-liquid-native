#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path


TREE_LINE = re.compile(r"^(\d+)(.+)\|([^|]*)$")
PACKAGE = re.compile(r"^(.+) v(\S+?)(?: \((.*)\))?$")


def package_label(
    package: dict, workspace_members: set[str], workspace_root: Path
) -> str:
    base = f'{package["name"]} v{package["version"]}'
    manifest_parent = Path(package["manifest_path"]).resolve().parent
    if package["id"] in workspace_members:
        relative = manifest_parent.relative_to(workspace_root)
        return f"{base} (workspace:{relative or Path('.')})"
    source = package.get("source")
    if source is None:
        try:
            relative = manifest_parent.relative_to(workspace_root)
            return f"{base} (path:{relative})"
        except ValueError:
            return f"{base} (path-outside-workspace)"
    checksum = package.get("checksum")
    if checksum is not None:
        return f"{base} ({source};checksum={checksum})"
    return f"{base} ({source})"


def tree_package_id(display: str, packages: dict[str, dict]) -> str:
    parsed = PACKAGE.fullmatch(display)
    if parsed is None:
        raise ValueError(f"invalid cargo tree package display: {display}")
    name, version, source_hint = parsed.groups()
    candidates = [
        package
        for package in packages.values()
        if package["name"] == name and package["version"] == version
    ]
    if source_hint is None:
        candidates = [
            package
            for package in candidates
            if (package.get("source") or "").startswith("registry+")
        ]
    elif source_hint.startswith("https://"):
        git_prefix = f"git+{source_hint.split('#', 1)[0]}#"
        candidates = [
            package
            for package in candidates
            if (package.get("source") or "").startswith(git_prefix)
        ]
    else:
        expected_path = Path(source_hint).resolve()
        candidates = [
            package
            for package in candidates
            if Path(package["manifest_path"]).resolve().parent == expected_path
        ]
    if len(candidates) != 1:
        raise ValueError(f"cargo tree package did not resolve uniquely: {display}")
    return candidates[0]["id"]


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: canonicalize-dependency-edges.py TREE METADATA")
    tree_path, metadata_path = map(Path, sys.argv[1:])
    metadata = json.loads(metadata_path.read_text())
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    workspace_members = set(metadata["workspace_members"])
    workspace_root = Path(metadata["workspace_root"]).resolve()

    active_edges = set()
    stack = {}
    for line in tree_path.read_text().splitlines():
        if not line:
            stack.clear()
            continue
        parsed = TREE_LINE.fullmatch(line)
        if parsed is None:
            raise ValueError(f"invalid cargo tree depth line: {line}")
        depth = int(parsed.group(1))
        package_id = tree_package_id(parsed.group(2), packages)
        stack = {level: value for level, value in stack.items() if level < depth}
        if depth > 0:
            if depth - 1 not in stack:
                raise ValueError(f"cargo tree depth skipped a parent: {line}")
            active_edges.add((stack[depth - 1], package_id))
        stack[depth] = package_id

    edges = set()
    for parent_id, child_id in active_edges:
        parent = package_label(packages[parent_id], workspace_members, workspace_root)
        child = package_label(packages[child_id], workspace_members, workspace_root)
        matching_dependencies = [
            dependency
            for dependency in nodes[parent_id]["deps"]
            if dependency["pkg"] == child_id
        ]
        if not matching_dependencies:
            raise ValueError(f"active dependency edge is absent from metadata: {parent} -> {child}")
        emitted = False
        for dependency in matching_dependencies:
            for item in dependency["dep_kinds"]:
                kind = item.get("kind")
                if kind == "dev":
                    continue
                emitted = True
                target = item.get("target") or "all"
                edges.add(
                    "|".join(
                        [
                            parent,
                            dependency["name"],
                            kind or "normal",
                            target,
                            child,
                        ]
                    )
                )
        if not emitted:
            raise ValueError(f"active dependency edge has only dev metadata: {parent} -> {child}")

    for edge in sorted(edges):
        print(edge)


if __name__ == "__main__":
    main()
