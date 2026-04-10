# Lightweight builder for xkey desktop application
# Based on Ubuntu 24.04 to match host runtime libraries (webkit2gtk-4.1, glibc 2.39)
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV GOTOOLCHAIN=auto
ENV GOFLAGS="-buildvcs=false"

# Install build dependencies
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
    # PKCS#11 support (miekg/pkcs11)
    libp11-kit-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Go (GOTOOLCHAIN=auto will fetch the exact version needed)
RUN curl -fsSL https://go.dev/dl/go1.26.1.linux-amd64.tar.gz | tar -C /usr/local -xzf -
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# Install Node.js 20.x LTS for Svelte/Vite frontend build
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
