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
# SoftHSM 2.7.0 from its pinned, checksum-verified release
# (scripts/build-softhsm.sh) instead of Ubuntu's 2.6.1, which answers an
# AES-GCM tag mismatch with the ambiguous CKR_GENERAL_ERROR (go-xkms#1418).
FROM ubuntu:24.04 AS softhsm
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf automake libtool pkg-config libssl-dev \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/build-softhsm.sh /build/build-softhsm.sh
RUN DESTDIR=/build/softhsm-install sh /build/build-softhsm.sh

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
# PKCS#11 / PIV simulation (SoftHSM2 + OpenSC tools + openssl)
# Required by test/e2e/setup-softhsm-piv.sh, which provisions a PIV token at
# /usr/lib/softhsm/libsofthsm2.so so the PIV-via-PKCS#11 GUI workflows run.
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    opensc \
    openssl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=softhsm /build/softhsm-install/ /

# ---------------------------------------------------------------------------
# Virtual display + image manipulation (headless GUI rendering)
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    xvfb \
    xdotool \
    imagemagick \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Go 1.27.1 (GOTOOLCHAIN=auto will fetch exact version if needed)
# ---------------------------------------------------------------------------
RUN curl -fsSL https://go.dev/dl/go1.27.1.linux-amd64.tar.gz | tar -C /usr/local -xzf -
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
# Wails CLI (needed for `wails dev`), rebuilt against a newer golang.org/x/tools.
# wails v2.12.0 pins x/tools v0.30.0, whose go/packages type-checker aborts with
# `internal error: package "github.com/jeremyhahn/go-qrdb/sdk/go" without types`
# when the bound type graph transitively reaches go-qrdb/sdk/go's generic DAO
# types (e.g. via the authenticator RP policy store). Bumping x/tools to v0.45.0 fixes the
# binding analysis so `wails dev` starts. The app's linked wails lib is unchanged.
RUN mkdir -p /tmp/wails-cli && cd /tmp/wails-cli && \
    GOFLAGS=-mod=mod GOWORK=off go mod init wailscli && \
    GOFLAGS=-mod=mod GOWORK=off go get github.com/wailsapp/wails/v2@v2.12.0 && \
    GOFLAGS=-mod=mod GOWORK=off go get golang.org/x/tools@v0.45.0 && \
    GOFLAGS=-mod=mod GOWORK=off go build -o /usr/local/bin/wails github.com/wailsapp/wails/v2/cmd/wails && \
    cd / && rm -rf /tmp/wails-cli && wails version

# ---------------------------------------------------------------------------
# Container setup
# ---------------------------------------------------------------------------
WORKDIR /workspace

COPY xkey/test/e2e/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
