#!/usr/bin/env python3
"""Run the vendored Karonte BDG core and export a stable JSON graph.

The parent process deliberately launches Karonte in a separate interpreter.
Karonte's pinned angr stack is old and should not become an import-time
dependency of the rest of FirmWELD.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from enum import Enum
from pathlib import Path

from runtime_state import write_json_atomic


DEFAULT_DATA_KEYS = ["QUERY_STRING", "username", "http_", "REMOTE_ADDR"]
KARONTE_COMMIT = "427ac313e596f723e40768b95d13bd7a9fc92fd8"


def _enabled(value: str | None) -> bool:
    return (value or "true").strip().lower() not in {"0", "false", "no", "off"}


def _tool_root(root: Path) -> Path:
    root = root.resolve()
    if (root / "tool" / "bdg" / "binary_dependency_graph.py").is_file():
        return root / "tool"
    if (root / "bdg" / "binary_dependency_graph.py").is_file():
        return root
    raise FileNotFoundError("Karonte BDG source was not found below {}".format(root))


def _guest_path(image_root: Path, binary: str) -> str:
    path = Path(os.path.abspath(binary))
    try:
        return "/" + path.relative_to(Path(os.path.abspath(image_root))).as_posix()
    except ValueError:
        return str(path)


def _resolve_guest_binary(image_root: Path, guest_path: str) -> Path:
    """Resolve absolute firmware symlinks inside image_root, not on the host."""

    root = Path(os.path.abspath(image_root))
    current = root / guest_path.lstrip("/")
    for _ in range(16):
        if not current.is_symlink():
            break
        target = os.readlink(current)
        if os.path.isabs(target):
            current = root / target.lstrip("/")
        else:
            current = current.parent / target
        current = Path(os.path.abspath(current))
        if os.path.commonpath((str(root), str(current))) != str(root):
            raise ValueError("firmware symlink escapes image root: {}".format(guest_path))
    return current


def _json_value(value):
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {str(_json_value(key)): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _serialize_graph(
    bdg, image_root: Path, seed: str, seed_guest: str, analysis_seconds: float
) -> dict:
    node_paths = {node: _guest_path(image_root, node.bin) for node in bdg.nodes}
    seed_host = os.path.abspath(seed)
    for node in bdg.nodes:
        if os.path.abspath(node.bin) == seed_host:
            node_paths[node] = seed_guest
    nodes = []
    for node in sorted(bdg.nodes, key=lambda item: node_paths[item]):
        nodes.append({
            "path": node_paths[node],
            "role": getattr(node.role, "name", str(node.role)),
            "root": bool(node.root),
            "leaf": bool(node.leaf),
            "orphan": bool(node.orphan),
            "data_keys": sorted({str(_json_value(key)) for key in node.role_data_keys if key}),
            "cpfs": sorted({getattr(cpf, "name", cpf.__class__.__name__) for cpf in node.cpfs}),
            "role_info": _json_value(node.role_info),
        })

    edges = []
    for producer, consumers in bdg.graph.items():
        for consumer in consumers:
            producer_keys = set(producer.role_data_keys)
            consumer_keys = set(consumer.role_data_keys)
            edges.append({
                "source": node_paths[producer],
                "target": node_paths[consumer],
                "data_keys": sorted(str(_json_value(key)) for key in producer_keys & consumer_keys if key),
            })
    edges.sort(key=lambda edge: (edge["source"], edge["target"]))
    result = {
        "schema_version": 1,
        "status": "success" if nodes else "empty",
        "usable": bool(nodes),
        "engine": "Karonte BinaryDependencyGraph",
        "karonte_commit": KARONTE_COMMIT,
        "graph_semantics": "producer_to_consumer",
        "seed_binary": seed_guest,
        "analysis_seconds": round(analysis_seconds, 3),
        "nodes": nodes,
        "edges": edges,
    }
    if not nodes:
        result["reason"] = "Karonte produced an empty graph; the seed may be unsupported"
    return result


def _worker(config_path: Path, output_path: Path) -> int:
    with config_path.open("r", encoding="utf-8") as handle:
        config = json.load(handle)
    tool_root = _tool_root(Path(config["tool_root"]))
    sys.path.insert(0, str(tool_root))

    from bdg.binary_dependency_graph import BinaryDependencyGraph
    from bdg.cpfs import environment, file, semantic, setter_getter, socket

    cpfs = [
        environment.Environment,
        file.File,
        socket.Socket,
        setter_getter.SetterGetter,
        semantic.Semantic,
    ]
    image_root = Path(config["image_root"]).resolve()
    seed = os.path.abspath(config["seed_binary"])
    seed_guest = config["seed_guest"]
    bdg = BinaryDependencyGraph(
        {"angr_explode_bins": config.get("ignore_binaries", [])},
        [seed],
        str(image_root),
        init_data_keys=config.get("init_data_keys", DEFAULT_DATA_KEYS),
        cpfs=cpfs,
    )
    started = time.monotonic()
    bdg.run()
    elapsed = time.monotonic() - started
    write_json_atomic(output_path, _serialize_graph(bdg, image_root, seed, seed_guest, elapsed))
    return 0


def _status(reason: str, status: str = "unavailable") -> dict:
    return {
        "schema_version": 1,
        "status": status,
        "usable": False,
        "engine": "Karonte BinaryDependencyGraph",
        "karonte_commit": KARONTE_COMMIT,
        "graph_semantics": "producer_to_consumer",
        "reason": reason,
        "nodes": [],
        "edges": [],
    }


def run_karonte_bdg(
    image_root: Path,
    seed_binary: str | None,
    output_path: Path,
    config_path: Path | None = None,
) -> dict:
    """Run Karonte out of process and always persist a machine-readable status."""

    if not _enabled(os.environ.get("FIRMWELD_KARONTE")):
        result = _status("disabled by FIRMWELD_KARONTE")
        write_json_atomic(output_path, result)
        return result
    if not seed_binary:
        result = _status("web service binary could not be resolved")
        write_json_atomic(output_path, result)
        return result

    try:
        seed_host = _resolve_guest_binary(image_root, seed_binary)
    except (OSError, ValueError) as error:
        result = _status("could not resolve seed binary {}: {}".format(seed_binary, error))
        write_json_atomic(output_path, result)
        return result
    if not seed_host.is_file():
        result = _status("seed binary does not exist: {}".format(seed_binary))
        write_json_atomic(output_path, result)
        return result

    default_root = Path(__file__).resolve().parents[1] / "third_party" / "karonte_bdg"
    configured_root = os.environ.get("FIRMWELD_KARONTE_ROOT", "").strip()
    karonte_root = Path(configured_root) if configured_root else default_root
    try:
        tool_root = _tool_root(karonte_root)
    except (FileNotFoundError, OSError) as error:
        result = _status(str(error))
        write_json_atomic(output_path, result)
        return result

    python = os.environ.get("FIRMWELD_KARONTE_PYTHON", "python3").strip() or "python3"
    try:
        timeout = max(1, int(os.environ.get("FIRMWELD_KARONTE_TIMEOUT", "900")))
    except ValueError:
        timeout = 900
    config = {
        "schema_version": 1,
        "tool_root": str(tool_root),
        "image_root": os.path.abspath(image_root),
        "seed_binary": os.path.abspath(seed_host),
        "seed_guest": seed_binary,
        "init_data_keys": DEFAULT_DATA_KEYS,
        "cpfs": ["environment", "file", "socket", "setter_getter", "semantic"],
        "ignore_binaries": [],
    }
    config_path = config_path or output_path.with_name("karonte_bdg_config.json")
    write_json_atomic(config_path, config)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix="karonte-bdg-", suffix=".json", dir=str(output_path.parent), delete=False
    ) as temporary:
        worker_output = Path(temporary.name)
    worker_output.unlink(missing_ok=True)
    command = [
        python,
        str(Path(__file__).resolve()),
        "--worker",
        "--config",
        str(config_path),
        "--output",
        str(worker_output),
    ]
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        if completed.returncode != 0 or not worker_output.is_file():
            detail = (completed.stderr or completed.stdout or "worker produced no output").strip()
            detail = detail[-2000:]
            result = _status("Karonte worker failed: {}".format(detail), "failed")
        else:
            with worker_output.open("r", encoding="utf-8") as handle:
                result = json.load(handle)
    except subprocess.TimeoutExpired:
        result = _status("Karonte exceeded the {} second limit".format(timeout), "timeout")
    except OSError as error:
        result = _status("could not launch {}: {}".format(python, error), "failed")
    finally:
        worker_output.unlink(missing_ok=True)

    write_json_atomic(output_path, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Export a Karonte BDG as JSON")
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.worker:
        parser.error("this entry point is reserved for the isolated worker")
    return _worker(args.config, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
