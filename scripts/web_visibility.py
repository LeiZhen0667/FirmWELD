#!/usr/bin/env python3
"""Plan and apply conservative web-root visibility interventions."""

from __future__ import annotations

import argparse
import json
import os
import shlex
from pathlib import Path, PurePosixPath

from runtime_state import write_json_atomic


def build_visibility_plan(state: dict, image_root: Path, service_command: str = "") -> dict:
    roots = [root for root in state.get("web_roots", []) if root != "/"]
    selected = roots[0] if roots else None
    references = service_command
    if service_command:
        command = service_command.split()[0]
        script = image_root / command.lstrip("/")
        if script.is_file():
            references += "\n" + script.read_text(encoding="utf-8", errors="ignore")
    mapping_known = bool(selected and selected in references)

    symlinks = []
    if selected and not mapping_known:
        root_parts = PurePosixPath(selected).parts
        root_depth = len(root_parts)
        for entry in state.get("filesystem", []):
            path = entry.get("path", "")
            parts = PurePosixPath(path).parts
            if len(parts) != root_depth + 1 or not path.startswith(selected.rstrip("/") + "/"):
                continue
            name = parts[-1]
            destination = image_root / name
            if not destination.exists() and not destination.is_symlink():
                symlinks.append({"source": path, "destination": "/" + name})

    return {
        "schema_version": 1,
        "selected_web_root": selected,
        "configuration_mapping_known": mapping_known,
        "symlinks": sorted(symlinks, key=lambda item: item["destination"]),
        "protected_roots": roots,
    }


def _wrapper(native_command: str, protected_roots: list[str]) -> str:
    roots = " ".join(shlex.quote(root) for root in protected_roots)
    return f"""#!/firmadyne/sh
BUSYBOX=/firmadyne/busybox
for ARG in "$@"; do
    case "$ARG" in -*) continue ;; esac
    TARGET=`$BUSYBOX readlink -f "$ARG" 2>/dev/null`
    [ -n "$TARGET" ] || TARGET="$ARG"
    for ROOT in {roots}; do
        case "$TARGET" in
            "$ROOT"|"$ROOT"/*)
                echo "[blocked-webroot] $0 $*" >> /firmadyne/webroot-protection.log
                exit 0
                ;;
        esac
    done
done
exec {native_command} "$@"
"""


def apply_visibility_plan(image_root: Path, plan: dict) -> None:
    for link in plan.get("symlinks", []):
        destination = image_root / link["destination"].lstrip("/")
        if destination.exists() or destination.is_symlink():
            continue
        os.symlink(link["source"], destination)

    roots = plan.get("protected_roots", [])
    if not roots:
        return
    wrapper_dir = image_root / "firmadyne" / "wrapper-bin"
    wrapper_dir.mkdir(parents=True, exist_ok=True)
    wrappers = {
        "rm": _wrapper("/bin/rm", roots),
        "unlink": _wrapper("/firmadyne/busybox unlink", roots),
    }
    for name, content in wrappers.items():
        path = wrapper_dir / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)


def main() -> int:
    parser = argparse.ArgumentParser(description="Restore and protect the detected web root")
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--image-root", required=True, type=Path)
    parser.add_argument("--service-command", default="")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    with args.state.open("r", encoding="utf-8") as handle:
        state = json.load(handle)
    plan = build_visibility_plan(state, args.image_root, args.service_command)
    write_json_atomic(args.output, plan)
    if args.apply:
        apply_visibility_plan(args.image_root, plan)
    print(f"Saved web visibility intervention to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
