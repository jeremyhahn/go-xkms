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

FROM golang:1.26.1-bookworm AS libfido2-builder

# Build libfido2 v1.17.0 from source for HID_NAME fallback support
RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential cmake pkg-config \
    libssl-dev libcbor-dev libudev-dev libpcsclite-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone --depth 1 --branch main https://github.com/Yubico/libfido2.git && \
    cd libfido2 && \
    mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr .. && \
    make -j$(nproc) && \
    make install DESTDIR=/build/libfido2-install

FROM golang:1.26.1-bookworm

# Allow Go to automatically download the required toolchain version
ENV GOTOOLCHAIN=auto

# Install FIDO2 runtime dependencies and development headers
RUN apt-get update && apt-get install -y \
    libcbor-dev \
    libhidapi-dev \
    libudev-dev \
    libpcsclite-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy built libfido2 v1.17.0 (library, headers, pkg-config, and CLI tools)
COPY --from=libfido2-builder /build/libfido2-install/usr /usr
RUN ldconfig

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire project
COPY . .

# Build the xkey binary for testing
RUN go build -o /usr/local/bin/xkey ./cmd/xkey

# Create test storage directory
RUN mkdir -p /var/lib/xkey

# Set environment variables
ENV CGO_ENABLED=1
ENV GOOS=linux

# Default command runs the integration tests
CMD ["go", "test", "-v", "-tags=integration,linux", "-timeout=5m", "./test/integration/xkey/..."]
