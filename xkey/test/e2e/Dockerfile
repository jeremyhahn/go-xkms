# Copyright (c) 2025 Jeremy Hahn
# Copyright (c) 2025 Automate The Things, LLC
#
# This file is part of go-xkms.
#
# go-xkms is dual-licensed:
#
# 1. GNU Affero General Public License v3.0 (AGPL-3.0)
#    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
#
# 2. Commercial License
#    Contact licensing@automatethethings.com for commercial licensing options.

# E2E testing environment for xKey GUI application
# Includes swtpm (software TPM 2.0), Playwright (headless Chromium),
# Xvfb (virtual display), and all Wails v2 build dependencies.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV GOTOOLCHAIN=auto
ENV GOFLAGS="-buildvcs=false"

# ---------------------------------------------------------------------------
# Core build tools + Wails v2 GUI dependencies
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core build tools
    build-essential \
    pkg-config \
    curl \
    ca-certificates \
    git \
    # Wails v2 GUI dependencies (GTK3, WebKit2GTK 4.1, libsoup3)
    libgtk-3-dev \
    libwebkit2gtk-4.1-dev \
    # BLE support (tinygo bluetooth)
    libbluetooth-dev \
    # USB support (google/gousb)
    libusb-1.0-0-dev \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# TPM simulation (swtpm + tpm2-tools)
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    swtpm \
    swtpm-tools \
    libtpms-dev \
    tpm2-tools \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Virtual display + image manipulation (headless GUI rendering)
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    xvfb \
    xdotool \
    imagemagick \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Go 1.26.1 (GOTOOLCHAIN=auto will fetch exact version if needed)
# ---------------------------------------------------------------------------
RUN curl -fsSL https://go.dev/dl/go1.26.1.linux-amd64.tar.gz | tar -C /usr/local -xzf -
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# ---------------------------------------------------------------------------
# Node.js 20.x LTS (Svelte/Vite frontend build + Playwright runtime)
# ---------------------------------------------------------------------------
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Playwright system dependencies + Chromium browser
# ---------------------------------------------------------------------------
RUN npx playwright install --with-deps chromium

# ---------------------------------------------------------------------------
# Wails CLI (needed for `wails dev`)
# ---------------------------------------------------------------------------
RUN go install github.com/wailsapp/wails/v2/cmd/wails@latest

# ---------------------------------------------------------------------------
# Container setup
# ---------------------------------------------------------------------------
WORKDIR /workspace

COPY xkey/test/e2e/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
