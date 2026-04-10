#!/usr/bin/env python3
"""Generate xKey brand icon assets from the website hero SVG."""

import os
import subprocess
import sys


def main() -> int:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    node_script = os.path.join(script_dir, "generate_icons.mjs")
    result = subprocess.run(["node", node_script], cwd=os.path.dirname(script_dir))
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
