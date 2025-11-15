# Multi-stage Dockerfile for go-keychain integration testing
# Supports PKCS#11 (SoftHSM2) and TPM 2.0 (SWTPM) testing

# Stage 1: Builder stage - compile dependencies and prepare environment
FROM golang:1.23-bookworm AS builder

# Allow Go to automatically download the required toolchain version
ENV GOTOOLCHAIN=auto

# Install build essentials and required packages for PKCS#11 and TPM testing
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libsofthsm2 \
    softhsm2 \
    opensc \
    swtpm \
    swtpm-tools \
    libtss2-dev \
    libtss2-esys-3.0.2-0 \
    libtss2-tcti-device0 \
    libtss2-tcti-swtpm0 \
    ca-certificates \
    git \
    automake \
    autoconf \
    libtool \
    libgnutls28-dev \
    libtasn1-6-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Build libtpms v0.10.1 from source to fix TPM_RC_RETRY issue
# See: https://github.com/stefanberger/libtpms/commit/37779b49
WORKDIR /build
RUN git clone https://github.com/stefanberger/libtpms.git && \
    cd libtpms && \
    git checkout v0.10.1 && \
    ./autogen.sh --prefix=/usr --with-openssl --with-tpm2 && \
    make -j$(nproc) && \
    make install DESTDIR=/build/libtpms-install

# Stage 2: Test runtime environment
FROM golang:1.23-bookworm

LABEL maintainer="go-keychain"
LABEL description="Integration testing environment for go-keychain with PKCS#11 and TPM 2.0 support"

# Allow Go to automatically download the required toolchain version
ENV GOTOOLCHAIN=auto

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsofthsm2 \
    softhsm2 \
    opensc \
    swtpm \
    swtpm-tools \
    libtss2-dev \
    libtss2-esys-3.0.2-0 \
    libtss2-tcti-device0 \
    libtss2-tcti-swtpm0 \
    ca-certificates \
    libgnutls30 \
    libtasn1-6 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Remove old libtpms installed by swtpm-libs package
RUN DPKG_ARCH=$(dpkg --print-architecture) && \
    case "${DPKG_ARCH}" in \
        amd64) ARCH=x86_64 ;; \
        arm64) ARCH=aarch64 ;; \
        armhf) ARCH=arm ;; \
        *) ARCH=${DPKG_ARCH} ;; \
    esac && \
    rm -f /usr/lib/${ARCH}-linux-gnu/libtpms.so* /lib/${ARCH}-linux-gnu/libtpms.so*

# Copy built libtpms v0.10.1 from builder stage
# This version fixes TPM_RC_RETRY issue in CheckLockedOut
COPY --from=builder /build/libtpms-install/usr /usr

# Create symlinks in the directory where SWTPM expects to find libtpms
RUN DPKG_ARCH=$(dpkg --print-architecture) && \
    case "${DPKG_ARCH}" in \
        amd64) ARCH=x86_64 ;; \
        arm64) ARCH=aarch64 ;; \
        armhf) ARCH=arm ;; \
        *) ARCH=${DPKG_ARCH} ;; \
    esac && \
    mkdir -p /lib/${ARCH}-linux-gnu && \
    ln -sf /usr/lib/libtpms.so.0.10.1 /lib/${ARCH}-linux-gnu/libtpms.so.0.10.1 && \
    ln -sf /lib/${ARCH}-linux-gnu/libtpms.so.0.10.1 /lib/${ARCH}-linux-gnu/libtpms.so.0 && \
    ln -sf /lib/${ARCH}-linux-gnu/libtpms.so.0.10.1 /lib/${ARCH}-linux-gnu/libtpms.so

# Update library cache to recognize new libtpms
RUN ldconfig

# Create non-root user for security best practices
RUN groupadd -r testuser -g 1000 && \
    useradd -r -u 1000 -g testuser -m -s /bin/bash testuser

# Create required directories with proper structure
RUN mkdir -p /workspace \
    /var/lib/softhsm/tokens \
    /var/lib/swtpm \
    /etc/softhsm \
    /etc/keychain \
    /data \
    /app \
    && chown -R testuser:testuser /workspace \
    && chown -R testuser:testuser /var/lib/softhsm \
    && chown -R testuser:testuser /var/lib/swtpm \
    && chown -R testuser:testuser /etc/softhsm \
    && chown -R testuser:testuser /etc/keychain \
    && chown -R testuser:testuser /data \
    && chown -R testuser:testuser /app

# Switch to non-root user
USER testuser

# Set working directory
WORKDIR /workspace

# Configure SoftHSM2
# Create SoftHSM configuration file pointing to our token directory
RUN echo "directories.tokendir = /var/lib/softhsm/tokens" > /etc/softhsm/softhsm2.conf && \
    echo "objectstore.backend = file" >> /etc/softhsm/softhsm2.conf && \
    echo "log.level = INFO" >> /etc/softhsm/softhsm2.conf

# Set SoftHSM2 configuration environment variable
ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf

# Initialize SoftHSM token for testing
# Token: test-token, SO PIN: 1234, User PIN: 1234, Slot: 0
RUN softhsm2-util --init-token --slot 0 --label "test-token" --so-pin 1234 --pin 1234

# Configure SWTPM environment
ENV SWTPM_STATE_DIR=/var/lib/swtpm
ENV TPM2TOOLS_TCTI=swtpm:path=/var/lib/swtpm/swtpm-sock

# Setup SWTPM state directory with proper permissions
RUN mkdir -p ${SWTPM_STATE_DIR}/state

# Copy go module files first for better layer caching
COPY --chown=testuser:testuser go.mod go.sum ./

# Download dependencies (cached if go.mod/go.sum unchanged)
RUN go mod download && go mod verify

# Copy the entire source code
COPY --chown=testuser:testuser . .

# Switch back to root to create entrypoint script in system location
USER root

# Create helper script to start SWTPM and run tests
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Start SWTPM in background\n\
echo "Starting SWTPM simulator..."\n\
swtpm socket --tpmstate dir=${SWTPM_STATE_DIR}/state \\\n\
  --tpm2 \\\n\
  --ctrl type=unixio,path=${SWTPM_STATE_DIR}/swtpm-sock \\\n\
  --flags startup-clear \\\n\
  --log level=1 &\n\
\n\
SWTPM_PID=$!\n\
sleep 2\n\
\n\
# Verify SWTPM is running\n\
if ! kill -0 ${SWTPM_PID} 2>/dev/null; then\n\
  echo "ERROR: SWTPM failed to start"\n\
  exit 1\n\
fi\n\
\n\
echo "SWTPM started with PID: ${SWTPM_PID}"\n\
\n\
# Verify SoftHSM token\n\
echo "Verifying SoftHSM token..."\n\
softhsm2-util --show-slots\n\
\n\
# Trap to cleanup on exit\n\
trap "kill ${SWTPM_PID} 2>/dev/null || true" EXIT\n\
\n\
# Run the command passed as arguments, default to integration tests\n\
if [ $# -eq 0 ]; then\n\
  echo "Running: make integration-test-local"\n\
  make integration-test-local\n\
else\n\
  echo "Running: $@"\n\
  exec "$@"\n\
fi\n' > /usr/local/bin/entrypoint.sh && chmod +x /usr/local/bin/entrypoint.sh

# Switch back to non-root user for security
USER testuser

# Build the server binary with all backends enabled
RUN mkdir -p /app && \
    CGO_ENABLED=1 go build -buildvcs=false -tags "pkcs8,tpm2,awskms,gcpkms,azurekv,pkcs11" \
    -o /app/keychain-server ./cmd/server/main.go

# Validate that the server binary exists
RUN test -f /app/keychain-server || (echo "ERROR: Server binary not built" && exit 1)

# Build the application with all backends enabled (optional, for validation)
RUN go build -buildvcs=false -tags "pkcs8,tpm2,awskms,gcpkms,azurekv,pkcs11" -v ./... 2>&1 | grep -v "build constraints exclude all Go files" || true

# Health check to verify SoftHSM is accessible
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD softhsm2-util --show-slots || exit 1

# Set the entrypoint to our helper script for test mode
# ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Default command runs integration tests
CMD ["/usr/local/bin/entrypoint.sh"]

# Expose any ports if needed (e.g., for debugging or metrics)
# EXPOSE 8080

# Volume mounts for persistent data if needed during development
VOLUME ["/var/lib/softhsm/tokens", "/var/lib/swtpm"]

# Environment variables for test configuration
ENV CGO_ENABLED=1
ENV GOCACHE=/tmp/go-cache
ENV GOFLAGS="-buildvcs=false"

# Labels for documentation and metadata
LABEL org.opencontainers.image.source="https://github.com/jeremyhahn/go-keychain"
LABEL org.opencontainers.image.description="Integration testing environment with SoftHSM2 and SWTPM"
LABEL org.opencontainers.image.vendor="go-keychain"
