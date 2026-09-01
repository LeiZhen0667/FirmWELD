#!/usr/bin/env python3
"""Collect the pre-emulation evidence used by FirmWELD interventions.

The collector intentionally consumes artifacts that the existing emulation
pipeline already produces.  It can therefore run after the first QEMU pass
without adding another privileged guest-side dependency.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import tempfile
from pathlib import Path


IP_HEADER = re.compile(r"^\s*\d+:\s+([^:]+):\s*<([^>]*)>\s*(.*)$")
IPV4 = re.compile(r"^\s*inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\b")
MAC = re.compile(r"^\s*link/(?:ether|loopback)\s+([0-9a-fA-F:]{17})\b")
NVRAM = re.compile(rb"^\[NVRAM\]\s+(\d+)\s+(.+)$")
EXEC_PATTERNS = (
    re.compile(r"\[execve-hook\].*?\bexe=([^\s]+)"),
    re.compile(r"\bexecve\(\s*[\"']([^\"']+)[\"']"),
    re.compile(r"\bdo_execve(?:at_common)?\b.*?([/][^\s]+)"),
)

WEB_EXTENSIONS = {
    ".html", ".htm", ".xhtml", ".shtml", ".asp", ".aspx", ".php",
    ".cgi", ".js", ".css", ".xml", ".json", ".svg", ".txt",
}
KNOWN_WEBROOTS = {
    "/www", "/web", "/htdocs", "/wwwroot", "/var/www", "/usr/www",
    "/usr/share/www", "/usr/share/htdocs", "/home/httpd", "/tmp/www",
}


def _read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def parse_ip_state(text: str) -> dict:
    interfaces: dict[str, dict] = {}
    current = None

    for line in text.splitlines():
        match = IP_HEADER.match(line)
        if match:
            raw_name, raw_flags, tail = match.groups()
            name = raw_name.split("@", 1)[0]
            lower = raw_name.split("@", 1)[1] if "@" in raw_name else None
            if lower is None and re.search(r"\.\d+$", name):
                lower = name.rsplit(".", 1)[0]
            master_match = re.search(r"\bmaster\s+([^\s]+)", tail)
            interfaces[name] = {
                "name": name,
                "raw_name": raw_name,
                "flags": [flag.strip().upper() for flag in raw_flags.split(",") if flag.strip()],
                "up": "UP" in raw_flags.upper().split(",") or bool(
                    re.search(r"\bstate\s+UP\b", tail, re.IGNORECASE)
                ),
                "master": master_match.group(1) if master_match else None,
                "lower": lower,
                "mac": None,
                "ipv4": [],
                "type": "other",
            }
            current = interfaces[name]
            continue

        if current is None:
            continue
        match = MAC.match(line)
        if match:
            current["mac"] = match.group(1).lower()
            continue
        match = IPV4.match(line)
        if match:
            current["ipv4"].append({"address": match.group(1), "prefixlen": int(match.group(2))})

    masters = {item["master"] for item in interfaces.values() if item.get("master")}
    for name, item in interfaces.items():
        if name == "lo":
            item["type"] = "loopback"
        elif re.match(r"^vlan\d+$", name, re.IGNORECASE) or re.search(r"\.\d+$", name):
            item["type"] = "vlan"
        elif name.startswith("br") or name in masters:
            item["type"] = "bridge"
        elif re.match(r"^(?:eth|en|lan)\w*\d", name, re.IGNORECASE):
            item["type"] = "ethernet"

    relations = []
    for item in interfaces.values():
        if item.get("master"):
            relations.append({"child": item["name"], "parent": item["master"], "kind": "master"})
        if item.get("lower"):
            relations.append({"child": item["name"], "parent": item["lower"], "kind": "lower"})

    return {"interfaces": list(interfaces.values()), "relations": relations}


def parse_processes(text: str) -> list[dict]:
    processes = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.upper().startswith("PID"):
            continue
        fields = stripped.split(None, 4)
        if not fields or not fields[0].isdigit():
            continue
        command = fields[-1] if len(fields) > 1 else ""
        processes.append({"pid": int(fields[0]), "command": command})
    return processes


def parse_nvram_keys(data: bytes) -> list[str]:
    keys = []
    seen = set()
    for line in data.splitlines():
        match = NVRAM.match(line)
        if not match:
            continue
        length = int(match.group(1))
        raw_key = match.group(2)[:length]
        key = raw_key.decode("utf-8", errors="ignore").strip("\x00")
        if key and key not in seen:
            seen.add(key)
            keys.append(key)
    return keys


def parse_exec_sequence(text: str) -> list[dict]:
    sequence = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        executable = None
        for pattern in EXEC_PATTERNS:
            match = pattern.search(line)
            if match:
                executable = match.group(1).rstrip(",;)")
                break
        if executable:
            sequence.append({"order": len(sequence), "line": line_number, "executable": executable})
    return sequence


def snapshot_filesystem(image_root: Path) -> list[dict]:
    if not image_root.is_dir():
        return []

    result = []
    for current_root, dirs, files in os.walk(image_root, topdown=True, followlinks=False):
        dirs.sort()
        files.sort()
        for name in dirs + files:
            host_path = Path(current_root) / name
            guest_path = "/" + str(host_path.relative_to(image_root))
            try:
                mode = host_path.lstat().st_mode
            except OSError:
                continue
            if stat.S_ISLNK(mode):
                kind = "symlink"
                try:
                    target = os.readlink(host_path)
                except OSError:
                    target = None
            elif stat.S_ISDIR(mode):
                kind, target = "directory", None
            elif stat.S_ISREG(mode):
                kind, target = "file", None
            elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                kind, target = "device", None
            else:
                kind, target = "other", None
            result.append({
                "path": guest_path,
                "kind": kind,
                "target": target,
                "executable": bool(mode & 0o111),
            })
    return result


def merge_runtime_filesystem(snapshot: list[dict], runtime_text: str) -> list[dict]:
    runtime_paths = []
    seen = set()
    for line in runtime_text.splitlines():
        path = line.strip()
        if not path.startswith("/") or path in seen:
            continue
        seen.add(path)
        runtime_paths.append(path.rstrip("/") or "/")
    if not runtime_paths:
        return snapshot
    by_path = {entry["path"]: entry for entry in snapshot}
    result = []
    for path in sorted(runtime_paths):
        entry = dict(by_path.get(path, {
            "path": path,
            "kind": "runtime_only",
            "target": None,
            "executable": False,
        }))
        entry["runtime_present"] = True
        result.append(entry)
    return result


def detect_web_roots(filesystem: list[dict]) -> list[str]:
    paths = {entry["path"] for entry in filesystem}
    candidates = set()
    for path in paths:
        suffix = Path(path).suffix.lower()
        if suffix not in WEB_EXTENSIONS:
            continue
        parent = str(Path(path).parent)
        if parent in KNOWN_WEBROOTS or Path(path).name.lower().startswith("index."):
            candidates.add(parent)
        for known_root in KNOWN_WEBROOTS:
            if path == known_root or path.startswith(known_root + "/"):
                candidates.add(known_root)
    return sorted(candidates, key=lambda value: (value.count("/"), value))


def collect_runtime_state(work_dir: Path, image_root: Path | None = None) -> dict:
    serial_path = work_dir / "qemu.initial.serial.log"
    serial_bytes = serial_path.read_bytes() if serial_path.exists() else b""
    serial_text = serial_bytes.decode("utf-8", errors="ignore")
    filesystem = snapshot_filesystem(image_root) if image_root else []
    filesystem = merge_runtime_filesystem(filesystem, _read_text(work_dir / "fs.log"))
    processes = parse_processes(_read_text(work_dir / "ps.log"))
    exec_sequence = parse_exec_sequence(serial_text)
    exec_source = "kernel_exec_hook"
    if not exec_sequence:
        exec_source = "process_pid_fallback"
        for item in sorted(processes, key=lambda value: value["pid"]):
            command = item.get("command", "").split()
            if command:
                exec_sequence.append({
                    "order": len(exec_sequence),
                    "line": None,
                    "executable": command[0],
                })
    return {
        "schema_version": 1,
        "network": parse_ip_state(_read_text(work_dir / "ip.log")),
        "processes": processes,
        "filesystem": filesystem,
        "web_roots": detect_web_roots(filesystem),
        "nvram_keys": parse_nvram_keys(serial_bytes),
        "exec_sequence": exec_sequence,
        "exec_sequence_source": exec_source,
        "sources": {
            "ip": str(work_dir / "ip.log"),
            "processes": str(work_dir / "ps.log"),
            "filesystem": str(work_dir / "fs.log"),
            "serial": str(serial_path),
            "image_root": str(image_root) if image_root else None,
        },
    }


def write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect FirmWELD pre-emulation state")
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--image-root", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or args.work_dir / "runtime_state.json"
    state = collect_runtime_state(args.work_dir, args.image_root)
    write_json_atomic(output, state)
    print(f"Saved runtime state to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
