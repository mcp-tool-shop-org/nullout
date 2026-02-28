"""Create hazardous fixtures for shipcheck.

Usage: python scripts/create_fixtures.py <root_dir>

Creates entries that trigger NullOut's hazard detection:
  - NUL.txt           (WIN_RESERVED_DEVICE_BASENAME)
  - emptydir.         (WIN_TRAILING_DOT_SPACE, empty directory)
  - notempty <space>   (WIN_TRAILING_DOT_SPACE, non-empty directory)

Uses \\\\?\\ extended path prefix to bypass Win32 name normalization.
"""

from __future__ import annotations

import os
import sys


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python create_fixtures.py <root_dir>", file=sys.stderr)
        sys.exit(1)

    root = sys.argv[1]
    if not os.path.isdir(root):
        print(f"Root does not exist: {root}", file=sys.stderr)
        sys.exit(1)

    ext = "\\\\?\\" + os.path.abspath(root)

    # 1. Reserved device basename file
    nul_path = ext + "\\NUL.txt"
    with open(nul_path, "w") as f:
        f.write("shipcheck fixture")
    print(f"  created: NUL.txt (reserved device name)")

    # 2. Empty directory with trailing dot
    dotdir = ext + "\\emptydir."
    os.makedirs(dotdir, exist_ok=True)
    print(f"  created: emptydir. (trailing dot, empty)")

    # 3. Non-empty directory with trailing space
    spacedir = ext + "\\notempty "
    os.makedirs(spacedir, exist_ok=True)
    with open(spacedir + "\\child.txt", "w") as f:
        f.write("x")
    print(f"  created: notempty<space> (trailing space, non-empty)")

    # Verify all exist
    ok = True
    for entry in os.scandir(ext):
        pass  # just make sure scandir works

    count = sum(1 for _ in os.scandir(ext))
    print(f"  root contains {count} entries")


if __name__ == "__main__":
    main()
