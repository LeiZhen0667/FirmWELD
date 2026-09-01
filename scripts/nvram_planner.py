#!/usr/bin/env python3
"""Generate per-firmware NVRAM completion entries from collected evidence."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from runtime_state import write_json_atomic


ASCII_STRING = re.compile(rb"[A-Za-z][A-Za-z0-9_.:-]{2,63}")
KEY_HINTS = (
    "lan", "wan", "wifi", "wlan", "http", "web", "admin", "ipaddr",
    "netmask", "bridge", "interface", "timezone", "dns", "dhcp",
)


def _host_path(image_root: Path, guest_path: str) -> Path:
    return image_root / guest_path.lstrip("/")


def _candidate_files(state: dict, image_root: Path, observed: list[str]) -> list[tuple[str, bytes]]:
    if not observed:
        return []
    threshold = max(2, len(observed) // 2)
    candidates = []
    observed_bytes = [key.encode("utf-8") for key in observed]
    for entry in state.get("filesystem", []):
        if entry.get("kind") != "file" or entry.get("path", "").startswith("/firmadyne/"):
            continue
        path = _host_path(image_root, entry["path"])
        try:
            if not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        overlap = sum(1 for key in observed_bytes if key in data)
        if overlap >= threshold:
            candidates.append((entry["path"], data))
    candidates.sort(key=lambda item: item[0])
    return candidates


def _looks_like_key(value: str, prefixes: set[str]) -> bool:
    lowered = value.lower()
    if "/" in value or value.startswith(".") or value.isdigit():
        return False
    if any(lowered.startswith(prefix) for prefix in prefixes if len(prefix) >= 2):
        return True
    return "_" in value and any(hint in lowered for hint in KEY_HINTS)


def build_nvram_plan(state: dict, image_root: Path, vendor_defaults: dict | None = None) -> dict:
    observed = sorted(set(state.get("nvram_keys", [])))
    prefixes = {key.lower().split("_", 1)[0] for key in observed}
    candidates = _candidate_files(state, image_root, observed)
    extracted = set()
    for _path, data in candidates:
        for match in ASCII_STRING.finditer(data):
            value = match.group(0).decode("ascii", errors="ignore")
            if value not in observed and _looks_like_key(value, prefixes):
                extracted.add(value)
    missing = sorted(extracted)[:512]
    defaults = vendor_defaults or {}
    entries = [
        {
            "key": key,
            "value": str(defaults.get(key, "")),
            "source": "vendor_dictionary" if key in defaults else "empty_fallback",
        }
        for key in missing
    ]
    return {
        "schema_version": 1,
        "observed_keys": observed,
        "configuration_files": [path for path, _data in candidates],
        "additional_keys": missing,
        "entries": entries,
    }


def apply_override(image_root: Path, plan: dict) -> None:
    override = image_root / "firmadyne" / "libnvram.override"
    override.mkdir(parents=True, exist_ok=True)
    for entry in plan.get("entries", []):
        key = entry["key"]
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{2,63}", key):
            continue
        (override / key).write_text(entry.get("value", ""), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate minimal NVRAM completion entries")
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--image-root", required=True, type=Path)
    parser.add_argument("--vendor-defaults", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    with args.state.open("r", encoding="utf-8") as handle:
        state = json.load(handle)
    defaults = {}
    if args.vendor_defaults and args.vendor_defaults.exists():
        with args.vendor_defaults.open("r", encoding="utf-8") as handle:
            defaults = json.load(handle)
    plan = build_nvram_plan(state, args.image_root, defaults)
    output = args.output or args.state.with_name("nvram_intervention.json")
    write_json_atomic(output, plan)
    if args.apply:
        apply_override(args.image_root, plan)
    print(f"Saved {len(plan['entries'])} NVRAM completion entries to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
