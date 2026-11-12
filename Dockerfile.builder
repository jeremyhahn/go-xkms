# Lightweight builder for go-xkms server and library builds
# Provides all CGO dependencies (libusb, PKCS#11) for portable binaries
FROM golang:1.27.4-bookworm

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
    # PKCS#11 tooling. No SoftHSM: this image only builds, and PKCS#11
    # modules are dlopen()ed at run time (go-xkms#1418).
    opensc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
