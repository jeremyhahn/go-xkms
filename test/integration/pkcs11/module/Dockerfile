# Dockerfile for PKCS#11 module integration testing
# Builds the PKCS#11 shared library and tests it with pkcs11-tool
#
# This container:
# - Builds the go-xkms PKCS#11 module (libxkms_pkcs11.so)
# - Installs OpenSC pkcs11-tool for compatibility testing
# - Runs integration tests against the built module
#
# Build: docker build -t xkms-pkcs11-module-test -f test/integration/pkcs11/module/Dockerfile .

# Stage 1: Builder - compile the PKCS#11 module
FROM golang:1.26.1-bookworm AS builder

# Allow Go to automatically download the required toolchain version
ENV GOTOOLCHAIN=auto
ENV CGO_ENABLED=1

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy go module files first for better caching
# Note: SDK directory must be copied before go mod download due to replace directive
COPY go.mod go.sum ./
COPY sdk/go/go.mod sdk/go/go.sum ./sdk/go/
RUN go mod download || true

# Copy source code
COPY . .

# Build the PKCS#11 shared library
RUN mkdir -p /build/lib && \
    CGO_ENABLED=1 go build -buildmode=c-shared \
        -o /build/lib/libxkms_pkcs11.so \
        ./cmd/pkcs11-module && \
    echo "PKCS#11 module built successfully"

# Stage 2: Test runtime environment
FROM golang:1.26.1-bookworm

LABEL maintainer="go-xkms"
LABEL description="PKCS#11 module integration test environment"

ENV GOTOOLCHAIN=auto
ENV CGO_ENABLED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install test dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build tools for CGO
    build-essential \
    gcc \
    g++ \
    pkg-config \
    # PKCS#11 testing tools
    opensc \
    opensc-pkcs11 \
    libengine-pkcs11-openssl \
    p11-kit \
    # SoftHSM2 for pkcs11 backend testing
    softhsm2 \
    libsofthsm2 \
    # Network utilities
    netcat-openbsd \
    curl \
    wget \
    # SSL/TLS
    libssl-dev \
    libssl3 \
    ca-certificates \
    # Development utilities
    jq \
    && rm -rf /var/lib/apt/lists/*

# Configure SoftHSM2
RUN mkdir -p /var/lib/softhsm/tokens /etc/softhsm && \
    echo "directories.tokendir = /var/lib/softhsm/tokens" > /etc/softhsm/softhsm2.conf && \
    echo "objectstore.backend = file" >> /etc/softhsm/softhsm2.conf && \
    echo "log.level = INFO" >> /etc/softhsm/softhsm2.conf && \
    chmod -R 755 /var/lib/softhsm

# Initialize SoftHSM token for testing
# Token label: "xkms-test", PIN: "1234", SO-PIN: "12345678"
# Token: xkms-test, SO PIN: 1234, User PIN: 1234, Slot: 0
RUN softhsm2-util --init-token --slot 0 --label "xkms-test" --pin 1234 --so-pin 1234

# Set SoftHSM environment variables
ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf
ENV SOFTHSM_LIBRARY=/usr/lib/softhsm/libsofthsm2.so

# Copy the built PKCS#11 module from builder
COPY --from=builder /build/lib/libxkms_pkcs11.so /usr/local/lib/
COPY --from=builder /build/lib/libxkms_pkcs11.h /usr/local/include/

# Create symlink for module discovery
RUN mkdir -p /usr/lib/pkcs11 && \
    ln -sf /usr/local/lib/libxkms_pkcs11.so /usr/lib/pkcs11/libxkms.so && \
    ldconfig

# Set up p11-kit module configuration
RUN mkdir -p /etc/pkcs11/modules && \
    echo "module: /usr/local/lib/libxkms_pkcs11.so" > /etc/pkcs11/modules/xkms.module

# Create test directories
RUN mkdir -p /app /data /var/run/xkms /etc/xkms

# Environment variables for PKCS#11 module configuration
ENV PKCS11_MODULE=/usr/local/lib/libxkms_pkcs11.so
ENV XKMS_PKCS11_CONFIG=/etc/xkms/pkcs11.yaml
ENV XKMS_UNIX_SOCKET=/var/run/xkms/xkms.sock
ENV XKMS_DATA_DIR=/data

WORKDIR /app

# Copy go module files for test execution
# Note: SDK directory must be copied before go mod download due to replace directive
COPY go.mod go.sum ./
COPY sdk/go/go.mod sdk/go/go.sum ./sdk/go/
RUN go mod download || true

# Copy test files and source
COPY . .

# Default: run integration tests
CMD ["sh", "-c", "/app/test/integration/pkcs11/module/run-tests.sh"]
