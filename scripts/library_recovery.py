#!/usr/bin/env python3
"""Recover missing web-service libraries from a compatible firmware pool."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from runtime_state import write_json_atomic


NEEDED = re.compile(r"Shared library:\s*\[([^\]]+)\]")
HEADER_FIELDS = ("Class", "Data", "Machine", "OS/ABI")


def _readelf(path: Path, option: str) -> str:
    try:
        return subprocess.check_output(
            ["readelf", option, str(path)],
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return ""


def elf_identity(path: Path) -> dict | None:
    output = _readelf(path, "-h")
    if not output:
        return None
    identity = {}
    for line in output.splitlines():
        stripped = line.strip()
        for field in HEADER_FIELDS:
            prefix = field + ":"
            if stripped.startswith(prefix):
                identity[field.lower().replace("/", "_")] = stripped[len(prefix):].strip()
    return identity if len(identity) == len(HEADER_FIELDS) else None


def needed_libraries(binary: Path) -> list[str]:
    return sorted(set(NEEDED.findall(_readelf(binary, "-d"))))


def _existing_names(image_root: Path) -> set[str]:
    names = set()
    for directory in (image_root / "lib", image_root / "usr/lib", image_root / "usr/local/lib"):
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if path.is_file() or path.is_symlink():
                names.add(path.name)
    return names


def _pool_candidates(pool: Path, name: str):
    for path in pool.rglob(name):
        if path.is_file():
            yield path


def build_library_plan(image_root: Path, pool: Path, binaries: list[str]) -> dict:
    existing = _existing_names(image_root)
    requests = []
    for guest_binary in sorted(set(binaries)):
        host_binary = image_root / guest_binary.lstrip("/")
        target_identity = elf_identity(host_binary)
        if target_identity is None:
            continue
        for library in needed_libraries(host_binary):
            if library in existing:
                continue
            selected = None
            for candidate in _pool_candidates(pool, library):
                if elf_identity(candidate) == target_identity:
                    selected = candidate
                    break
            requests.append({
                "required_by": guest_binary,
                "library": library,
                "source": str(selected) if selected else None,
                "destination": "/lib/" + library,
                "compatible": selected is not None,
                "elf_identity": target_identity,
            })
    return {
        "schema_version": 1,
        "pool": str(pool),
        "binaries": sorted(set(binaries)),
        "recoveries": requests,
    }


def apply_recoveries(image_root: Path, plan: dict) -> int:
    copied = 0
    for recovery in plan.get("recoveries", []):
        if not recovery.get("compatible") or not recovery.get("source"):
            continue
        source = Path(recovery["source"])
        destination = image_root / recovery["destination"].lstrip("/")
        if destination.exists() or not source.is_file():
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        copied += 1
    return copied


def main() -> int:
    parser = argparse.ArgumentParser(description="Recover compatible missing shared libraries")
    parser.add_argument("--image-root", required=True, type=Path)
    parser.add_argument("--pool", required=True, type=Path)
    parser.add_argument("--binary", action="append", default=[])
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    plan = build_library_plan(args.image_root, args.pool, args.binary)
    write_json_atomic(args.output, plan)
    copied = apply_recoveries(args.image_root, plan) if args.apply else 0
    print(f"Planned {len(plan['recoveries'])} missing libraries; copied {copied}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
