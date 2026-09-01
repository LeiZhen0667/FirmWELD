"""Shell-free firmware binary searches used by the selected Karonte CPFs."""

import mmap
import os


def find_elf_files_containing(fw_path, needles):
    """Return ELF files below fw_path containing every byte/string needle."""

    encoded = []
    for needle in needles:
        if needle is None:
            continue
        value = needle if isinstance(needle, bytes) else str(needle).encode('utf-8', errors='ignore')
        if value:
            encoded.append(value)
    if not encoded:
        return []

    matches = []
    for directory, dirnames, filenames in os.walk(fw_path, followlinks=False):
        dirnames[:] = [
            name for name in dirnames
            if not os.path.islink(os.path.join(directory, name))
        ]
        for name in filenames:
            path = os.path.join(directory, name)
            if os.path.islink(path):
                continue
            try:
                with open(path, 'rb') as handle:
                    if handle.read(4) != b'\x7fELF':
                        continue
                    handle.seek(0)
                    with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as content:
                        if all(content.find(needle) >= 0 for needle in encoded):
                            matches.append(path)
            except (OSError, ValueError):
                continue
    return matches
