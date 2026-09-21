# Lightweight builder for go-xkms server and library builds
# Provides all CGO dependencies (libusb, PKCS#11) for portable binaries
FROM golang:1.27.0-bookworm

ENV GOTOOLCHAIN=auto
ENV GOFLAGS="-buildvcs=false"

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    ca-certificates \
    git \
    # USB support (google/gousb → phone backend)
    libusb-1.0-0-dev \
    # ICU regex (dolthub/go-icu-regex via the qrdb SQL engine)
    libicu-dev \
    # PKCS#11 support
    libsofthsm2 \
    softhsm2 \
    opensc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
