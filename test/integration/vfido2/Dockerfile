# Copyright (c) 2025 Jeremy Hahn
# Copyright (c) 2025 Automate The Things, LLC
#
# This file is part of go-keychain.
#
# go-keychain is dual-licensed:
#
# 1. GNU Affero General Public License v3.0 (AGPL-3.0)
#    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
#
# 2. Commercial License
#    Contact licensing@automatethethings.com for commercial licensing options.

FROM golang:bookworm

# Allow Go to automatically download the required toolchain version
ENV GOTOOLCHAIN=auto

# Install FIDO2 development libraries and tools
RUN apt-get update && apt-get install -y \
    libfido2-dev \
    fido2-tools \
    libhidapi-dev \
    libudev-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire project
COPY . .

# Build the vfido2 binary for testing
RUN go build -o /usr/local/bin/vfido2 ./cmd/vfido2

# Create test storage directory
RUN mkdir -p /var/lib/vfido2

# Set environment variables
ENV CGO_ENABLED=1
ENV GOOS=linux

# Default command runs the integration tests
CMD ["go", "test", "-v", "-tags=integration,linux", "-timeout=5m", "./test/integration/vfido2/..."]
