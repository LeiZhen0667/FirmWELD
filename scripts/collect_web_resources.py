#!/usr/bin/env python3
"""Collect runtime web responses using paths observed in the firmware image."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

from runtime_state import WEB_EXTENSIONS, write_json_atomic


def _read_words(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8", errors="ignore").split()


def resource_paths(state: dict) -> list[str]:
    roots = state.get("web_roots", [])
    result = set()
    for entry in state.get("filesystem", []):
        path = entry.get("path", "")
        if entry.get("kind") not in ("file", "symlink", "runtime_only"):
            continue
        if PurePosixPath(path).suffix.lower() not in WEB_EXTENSIONS:
            continue
        for root in roots:
            prefix = root.rstrip("/") + "/"
            if path.startswith(prefix):
                relative = path[len(prefix):]
                if relative and ".." not in PurePosixPath(relative).parts:
                    result.add("/" + relative)
                break
    return sorted(result)


def endpoints(work_dir: Path) -> list[tuple[str, str, str]]:
    ips = _read_words(work_dir / "ip")
    ports = _read_words(work_dir / "web_ports") or ["80", "443"]
    result = []
    for ip in ips:
        for port in ports:
            if not port.isdigit():
                continue
            schemes = ("https", "http") if port == "443" else ("http", "https")
            for scheme in schemes:
                result.append((scheme, ip, port))
    return result


def _valid_content(data: bytes, content_type: str) -> bool:
    if not data or not data.strip():
        return False
    lowered = data[:8192].lower()
    if b"500 internal server error" in lowered or b"404 not found" in lowered:
        return False
    if "html" in content_type and b"<html" not in lowered and b"<script" not in lowered:
        return False
    return True


def fetch_resource(path: str, candidates, timeout: float) -> dict | None:
    quoted_path = urllib.parse.quote(path, safe="/%?=&:+,;@")
    context = ssl._create_unverified_context()
    headers = {"User-Agent": "FirmWELD-runtime-collector/1.0", "Connection": "close"}
    for scheme, ip, port in candidates:
        url = f"{scheme}://{ip}:{port}{quoted_path}"
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                status = int(response.getcode() or 0)
                data = response.read(8 * 1024 * 1024 + 1)
                if status < 200 or status >= 300 or len(data) > 8 * 1024 * 1024:
                    continue
                content_type = response.headers.get_content_type() or "application/octet-stream"
                if not _valid_content(data, content_type):
                    continue
                return {
                    "path": path,
                    "url": response.geturl(),
                    "status": status,
                    "content_type": content_type,
                    "content": data,
                }
        except (urllib.error.URLError, OSError, TimeoutError, ValueError):
            continue
    return None


def _archive_path(root: Path, resource_path: str) -> Path:
    relative = PurePosixPath(resource_path.lstrip("/"))
    parts = [part for part in relative.parts if part not in ("", ".", "..")]
    return root.joinpath(*parts)


def collect(
    work_dir: Path,
    output_dir: Path,
    timeout: float,
    workers: int,
    limit: int,
    overall_timeout: float = 240.0,
) -> dict:
    state_path = work_dir / "runtime_state.json"
    with state_path.open("r", encoding="utf-8") as handle:
        state = json.load(handle)
    paths = resource_paths(state)[:limit]
    candidate_endpoints = endpoints(work_dir)
    pages_dir = output_dir / "pages"
    pages_dir.mkdir(parents=True, exist_ok=True)

    fetched = []
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    future_map = {}
    try:
        future_map = {
            executor.submit(fetch_resource, path, candidate_endpoints, timeout): path
            for path in paths
        }
        for future in concurrent.futures.as_completed(future_map, timeout=overall_timeout):
            result = future.result()
            if result is None:
                continue
            destination = _archive_path(pages_dir, result["path"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=destination.name + ".", dir=destination.parent)
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(result.pop("content"))
                os.replace(temporary, destination)
            except Exception:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
                raise
            result["archive_path"] = str(destination.relative_to(output_dir))
            fetched.append(result)
    except concurrent.futures.TimeoutError:
        pass
    finally:
        for future in future_map:
            future.cancel()
        executor.shutdown(wait=False)

    manifest = {
        "schema_version": 1,
        "firmware_id": work_dir.name,
        "brand": " ".join(_read_words(work_dir / "brand")),
        "firmware_name": " ".join(_read_words(work_dir / "name")),
        "web_roots": state.get("web_roots", []),
        "candidate_path_count": len(paths),
        "collected_count": len(fetched),
        "resources": sorted(fetched, key=lambda item: item["path"]),
    }
    write_json_atomic(output_dir / "manifest.json", manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Archive validated runtime web resources")
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--limit", type=int, default=2000)
    parser.add_argument("--overall-timeout", type=float, default=240.0)
    args = parser.parse_args()
    output = args.output_dir or args.work_dir / "web_resources"
    manifest = collect(
        args.work_dir,
        output,
        args.timeout,
        max(1, args.workers),
        max(1, args.limit),
        max(1.0, args.overall_timeout),
    )
    print(f"Collected {manifest['collected_count']} of {manifest['candidate_path_count']} candidate resources")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
