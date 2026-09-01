#!/usr/bin/env python3
"""Export collected runtime responses in the directory layout DeepFW reads."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
from pathlib import Path


def safe_category(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._+-]+", "_", value.strip())
    return cleaned.strip("._") or "unknown_firmware"


def export(manifest_path: Path, output_root: Path) -> tuple[Path, int]:
    with manifest_path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    category = safe_category(manifest.get("firmware_name") or manifest.get("firmware_id", ""))
    destination_root = output_root / category
    destination_root.mkdir(parents=True, exist_ok=True)
    source_root = manifest_path.parent
    exported = 0

    for resource in manifest.get("resources", []):
        source = source_root / resource["archive_path"]
        relative = Path(resource["path"].lstrip("/"))
        if ".." in relative.parts or not source.is_file():
            continue
        destination = destination_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            destination.unlink()
        try:
            os.link(source, destination)
        except OSError:
            shutil.copy2(source, destination)
        exported += 1

    metadata = {
        "firmware_id": manifest.get("firmware_id"),
        "firmware_name": manifest.get("firmware_name"),
        "brand": manifest.get("brand"),
        "source_manifest": str(manifest_path),
        "exported_count": exported,
    }
    with (destination_root / "metadata.json").open("w", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return destination_root, exported


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a DeepFW-compatible runtime page dataset")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    args = parser.parse_args()
    destination, count = export(args.manifest, args.output_root)
    print(f"Exported {count} runtime pages to {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
