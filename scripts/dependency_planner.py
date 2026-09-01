#!/usr/bin/env python3
"""Build a BDG-guided, evidence-constrained IPC startup plan."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import stat
from pathlib import Path

from runtime_state import write_json_atomic


IPC_NAMES = {
    "ubusd", "netifd", "procd", "dbus-daemon", "rpcd", "dnsmasq",
    "udhcpd", "cfgmgr", "nvramd", "msgd", "eventd",
}
ABSOLUTE_EXECUTABLE = re.compile(r"(?<![A-Za-z0-9_])(/(?:sbin|bin|usr/sbin|usr/bin)/[A-Za-z0-9_.+-]+)")


def _guest_to_host(image_root: Path, guest_path: str) -> Path:
    return image_root / guest_path.lstrip("/")


def _find_binary(image_root: Path, name: str) -> str | None:
    for prefix in ("/sbin", "/usr/sbin", "/bin", "/usr/bin"):
        candidate = prefix + "/" + name
        if _guest_to_host(image_root, candidate).is_file():
            return candidate
    return None


def _service_identity(service_command: str) -> tuple[str, str]:
    tokens = shlex.split(service_command)
    if not tokens:
        return "", ""
    command_path = tokens[0]
    service_name = os.path.basename(command_path)
    if "/init.d/" in command_path:
        service_name = os.path.basename(command_path)
    return command_path, service_name


def resolve_service_binary(image_root: Path, service_command: str) -> str | None:
    command_path, service_name = _service_identity(service_command)
    if command_path and "/init.d/" not in command_path:
        if _guest_to_host(image_root, command_path).is_file():
            return command_path
    return _find_binary(image_root, service_name)


def _startup_references(image_root: Path, service_command: str) -> set[str]:
    command_path, service_name = _service_identity(service_command)
    references = set()
    host_script = _guest_to_host(image_root, command_path)
    if host_script.is_file():
        text = host_script.read_text(encoding="utf-8", errors="ignore")
        for match in ABSOLUTE_EXECUTABLE.finditer(text):
            path = match.group(1)
            name = os.path.basename(path)
            if (
                name in IPC_NAMES
                and name != service_name
                and _guest_to_host(image_root, path).is_file()
            ):
                references.add(path)
    return references


def _upstream_closure(bdg: dict, web_binary: str | None) -> tuple[list[str], list[tuple[str, str]]]:
    if not bdg or not bdg.get("usable") or not web_binary:
        return [], []
    nodes = {item.get("path", "") for item in bdg.get("nodes", []) if item.get("path")}
    if web_binary not in nodes:
        same_name = sorted(path for path in nodes if os.path.basename(path) == os.path.basename(web_binary))
        if len(same_name) != 1:
            return [], []
        web_binary = same_name[0]
    edges = [
        (item.get("source", ""), item.get("target", ""))
        for item in bdg.get("edges", [])
        if item.get("source") in nodes and item.get("target") in nodes
    ]
    parents: dict[str, set[str]] = {path: set() for path in nodes}
    for producer, consumer in edges:
        parents[consumer].add(producer)
    closure = {web_binary}
    pending = [web_binary]
    while pending:
        current = pending.pop()
        for parent in parents.get(current, ()):
            if parent not in closure:
                closure.add(parent)
                pending.append(parent)
    return sorted(closure), edges


def _is_request_handler(path: str, web_binary: str | None) -> bool:
    lower = path.lower()
    return path == web_binary or "/cgi-bin/" in lower or lower.endswith((".cgi", ".php", ".asp"))


def _is_executable(image_root: Path, guest_path: str) -> bool:
    host = _guest_to_host(image_root, guest_path)
    try:
        mode = host.stat().st_mode
    except OSError:
        return False
    return host.is_file() and bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def _topological_order(paths: list[str], edges: list[tuple[str, str]], observed_order: dict[str, int]) -> list[str]:
    selected = set(paths)
    children = {path: set() for path in selected}
    indegree = {path: 0 for path in selected}
    for producer, consumer in edges:
        if producer in selected and consumer in selected and consumer not in children[producer]:
            children[producer].add(consumer)
            indegree[consumer] += 1

    def key(path: str):
        name = os.path.basename(path)
        return (name not in observed_order, observed_order.get(name, 1 << 30), path)

    ready = sorted((path for path, degree in indegree.items() if degree == 0), key=key)
    ordered = []
    while ready:
        current = ready.pop(0)
        ordered.append(current)
        for child in sorted(children[current], key=key):
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
                ready.sort(key=key)
    ordered.extend(sorted(selected - set(ordered), key=key))
    return ordered


def build_ipc_plan(state: dict, image_root: Path, service_command: str, bdg: dict | None = None) -> dict:
    _, service_name = _service_identity(service_command)
    running = {
        os.path.basename(item.get("command", "").split()[0])
        for item in state.get("processes", [])
        if item.get("command")
    }
    startup_references = _startup_references(image_root, service_command)

    observed = []
    observed_order: dict[str, int] = {}
    service_order = None
    for item in state.get("exec_sequence", []):
        executable = item.get("executable", "")
        name = os.path.basename(executable)
        observed_order.setdefault(name, item.get("order", len(observed)))
        if name == service_name and service_order is None:
            service_order = item.get("order", len(observed))
        observed.append((item.get("order", len(observed)), executable, name))

    candidates: dict[str, dict] = {}
    web_binary = resolve_service_binary(image_root, service_command)
    scand, bdg_edges = _upstream_closure(bdg or {}, web_binary)
    # A seed-only graph contains no actionable dependency evidence. Preserve it
    # in Scand for diagnostics, but use the runtime/startup fallback for Dboot.
    bdg_used = len(scand) > 1

    if bdg_used:
        boot_evidence = set(running) | set(observed_order) | IPC_NAMES
        for path in scand:
            name = os.path.basename(path)
            if _is_request_handler(path, web_binary) or not _is_executable(image_root, path):
                continue
            if path not in startup_references and name not in boot_evidence:
                continue
            candidates[name] = {
                "binary": path,
                "evidence": "karonte_bdg",
                "observed_order": observed_order.get(name),
            }
    for path in startup_references:
        if bdg_used and path not in scand:
            continue
        name = os.path.basename(path)
        candidates.setdefault(name, {"binary": path, "evidence": "startup_script", "observed_order": None})

    for order, executable, name in observed:
        if name not in IPC_NAMES:
            continue
        if service_order is not None and order > service_order:
            continue
        path = executable if executable.startswith("/") else _find_binary(image_root, name)
        if bdg_used and path not in scand:
            continue
        if path and _guest_to_host(image_root, path).is_file():
            candidates.setdefault(name, {
                "binary": path,
                "evidence": "exec_sequence",
                "observed_order": order,
            })

    if service_name == "uhttpd" and "ubusd" not in candidates:
        ubusd = _find_binary(image_root, "ubusd")
        if ubusd and (not bdg_used or ubusd in scand):
            candidates["ubusd"] = {
                "binary": ubusd,
                "evidence": "uhttpd_runtime_prerequisite",
                "observed_order": None,
            }

    dboot = sorted(value["binary"] for value in candidates.values())
    missing_by_path = {}
    for name, value in candidates.items():
        if name in running:
            continue
        item = dict(value)
        item["name"] = name
        missing_by_path[item["binary"]] = item
    ordered_paths = _topological_order(list(missing_by_path), bdg_edges, observed_order)
    missing = [missing_by_path[path] for path in ordered_paths]
    for index, item in enumerate(missing):
        item["order"] = index
        item["command"] = shlex.quote(item["binary"]) + " &"

    return {
        "schema_version": 2,
        "web_service": service_command,
        "web_binary": web_binary,
        "candidate_source": (
            "karonte-bdg-and-runtime-evidence" if bdg_used
            else "startup-script-and-runtime-evidence-fallback"
        ),
        "bdg_used": bdg_used,
        "scand": scand,
        "dboot": dboot,
        "dmiss": ordered_paths,
        "running_process_names": sorted(running),
        "missing_daemons": missing,
        "commands": [item["command"] for item in missing],
    }


def write_guest_plan(path: Path, plan: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for command in plan.get("commands", []):
            handle.write(command.rstrip() + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate ordered IPC recovery commands")
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--image-root", required=True, type=Path)
    parser.add_argument("--service-command")
    parser.add_argument("--service-file", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--guest-plan", type=Path)
    args = parser.parse_args()
    service_command = args.service_command
    if not service_command and args.service_file and args.service_file.exists():
        service_command = args.service_file.read_text(encoding="utf-8", errors="ignore").strip()
    if not service_command:
        raise SystemExit("A service command is required")
    with args.state.open("r", encoding="utf-8") as handle:
        state = json.load(handle)
    plan = build_ipc_plan(state, args.image_root, service_command)
    output = args.output or args.state.with_name("ipc_intervention.json")
    write_json_atomic(output, plan)
    if args.guest_plan:
        write_guest_plan(args.guest_plan, plan)
    print(f"Saved IPC intervention to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
