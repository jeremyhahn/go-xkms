#!/bin/bash
# Build xKey browser extension for Chrome and/or Firefox.
#
# Usage:
#   ./build.sh              # Build for Chrome (default) → dist/
#   ./build.sh chrome       # Build for Chrome → dist/
#   ./build.sh firefox      # Build for Firefox → dist-firefox/ + .xpi
#   ./build.sh all          # Build for both browsers
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BROWSER="${1:-chrome}"

# Install deps if needed.
if [ ! -d node_modules ]; then
  npm install --silent
fi

# compile_ts runs the TypeScript compiler once into dist/.
compile_ts() {
  rm -rf dist
  node node_modules/typescript/lib/tsc.js
}

# copy_static copies popup.html and icons into the given output directory.
copy_static() {
  local out="$1"
  cp src/popup.html "$out/"
  mkdir -p "$out/icons"
  if ls src/icons/* 1>/dev/null 2>&1; then
    cp -r src/icons/* "$out/icons/"
  fi
}

# build_chrome produces the Chrome build in dist/.
build_chrome() {
  echo "Building xKey extension for Chrome..."
  compile_ts
  cp manifest.json dist/
  copy_static dist
  echo "Chrome build complete → dist/"
  echo "  Load as unpacked extension from dist/ in chrome://extensions"
}

# build_firefox produces the Firefox build in dist-firefox/ and packages an .xpi.
build_firefox() {
  echo "Building xKey extension for Firefox..."

  # Compile TS if dist/ doesn't exist yet (shared JS output).
  if [ ! -d dist ]; then
    compile_ts
  fi

  rm -rf dist-firefox
  mkdir -p dist-firefox

  # Copy compiled JS and source maps.
  cp dist/*.js dist-firefox/
  cp dist/*.js.map dist-firefox/ 2>/dev/null || true

  # Generate Firefox-compatible manifest:
  #   - Remove Chrome-specific "key" field
  #   - Replace service_worker with scripts array (Firefox < 128 compat)
  node -e '
    const fs = require("fs");
    const m = JSON.parse(fs.readFileSync("manifest.json", "utf8"));

    // Remove Chrome-specific key (used to pin Chrome extension ID).
    delete m.key;

    // Firefox MV3: use background scripts instead of service_worker.
    // Firefox 128+ supports service_worker, but scripts works on all
    // MV3-capable Firefox versions (109+).
    if (m.background && m.background.service_worker) {
      const worker = m.background.service_worker;
      m.background = { scripts: [worker], type: "module" };
    }

    fs.writeFileSync("dist-firefox/manifest.json", JSON.stringify(m, null, 2) + "\n");
  '

  copy_static dist-firefox

  # Package as .xpi (signed or unsigned for development).
  (cd dist-firefox && zip -qr ../xkey-autofill.xpi .)
  echo "Firefox build complete → dist-firefox/"
  echo "  Temporary: about:debugging → Load Temporary Add-on → select dist-firefox/manifest.json"
  echo "  Package:   xkey-autofill.xpi"
}

case "$BROWSER" in
  chrome)
    build_chrome
    ;;
  firefox)
    build_firefox
    ;;
  all)
    build_chrome
    build_firefox
    ;;
  *)
    echo "Usage: $0 [chrome|firefox|all]" >&2
    exit 1
    ;;
esac
