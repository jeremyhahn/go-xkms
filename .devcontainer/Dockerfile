# go-xkms Development Container
# This container provides ALL dependencies needed for development and testing
# Go Version: Latest stable via golang:1.26.1-bookworm (GOTOOLCHAIN=auto)
#
# Includes:
# - PKCS#11: SoftHSM2, OpenSC
# - TPM2: SWTPM simulator, libtpms v0.10.1, tpm2-tools
# - Quantum: pure-Go post-quantum cryptography (ML-DSA, ML-KEM) - no external deps
# - gRPC: protoc, grpcurl for protocol buffer development
# - Docker: docker-in-docker support for integration tests

# Stage 1: Builder stage - compile dependencies from source
FROM golang:1.26.1-bookworm AS builder

# Allow Go to automatically download the required toolchain version
ENV GOTOOLCHAIN=auto
ENV DEBIAN_FRONTEND=noninteractive

# Install all build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core build tools
    build-essential \
    gcc \
    g++ \
    make \
    pkg-config \
    git \
    automake \
    autoconf \
    libtool \
    # SSL/TLS development
    libssl-dev \
    libgnutls28-dev \
    libtasn1-6-dev \
    # PKCS#11 and smart card development
    libsofthsm2 \
    softhsm2 \
    opensc \
    opensc-pkcs11 \
    libpcsclite-dev \
    # TPM2 development
    swtpm \
    swtpm-tools \
    libtss2-dev \
    libtss2-esys-3.0.2-0 \
    libtss2-tcti-device0 \
    libtss2-tcti-swtpm0 \
    libusb-1.0-0-dev \
    flex \
    bison \
    curl \
    xz-utils \
    # FIDO2/WebAuthn build dependencies
    libcbor-dev \
    libudev-dev \
    cmake \
    zlib1g-dev \
    # Protobuf
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Install Go tools for protobuf/gRPC code generation
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Build libfido2 v1.17.0 from source for HID_NAME fallback support
# Ubuntu/Debian ship 1.14.0 which lacks UHID virtual device product name display
# See: https://github.com/Yubico/libfido2/commit/64e93db
WORKDIR /build
RUN git clone --depth 1 --branch main https://github.com/Yubico/libfido2.git && \
    cd libfido2 && \
    mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr .. && \
    make -j$(nproc) && \
    make install DESTDIR=/build/libfido2-install

# Build libtpms v0.10.1 from source to fix TPM_RC_RETRY issue
# See: https://github.com/stefanberger/libtpms/commit/37779b49
WORKDIR /build
RUN git clone https://github.com/stefanberger/libtpms.git && \
    cd libtpms && \
    git checkout v0.10.1 && \
    ./autogen.sh --prefix=/usr --with-openssl --with-tpm2 && \
    make -j$(nproc) && \
    make install DESTDIR=/build/libtpms-install

# Stage 2: Development runtime environment
FROM golang:1.26.1-bookworm

LABEL maintainer="go-xkms"
LABEL description="Development environment for go-xkms with ALL build and test dependencies"

# Allow Go to automatically download the required toolchain version
ENV GOTOOLCHAIN=auto
ENV DEBIAN_FRONTEND=noninteractive

# Install all runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core build tools (needed for CGO)
    build-essential \
    gcc \
    g++ \
    make \
    pkg-config \
    # Git and version control
    git \
    git-lfs \
    # SSL/TLS libraries
    libssl3 \
    libssl-dev \
    libgnutls30 \
    libtasn1-6 \
    # PKCS#11 and smart card
    libsofthsm2 \
    softhsm2 \
    opensc \
    opensc-pkcs11 \
    pcscd \
    libpcsclite1 \
    # TPM2 tools and libraries
    swtpm \
    swtpm-tools \
    libtss2-dev \
    libtss2-esys-3.0.2-0 \
    libtss2-tcti-device0 \
    libtss2-tcti-swtpm0 \
    tpm2-tools \
    libusb-1.0-0-dev \
    # FIDO2/WebAuthn runtime dependencies (library built from source in builder stage)
    libcbor0.8 \
    # Wails v2 GUI dependencies (GTK3, WebKit2GTK, libsoup3)
    libgtk-3-dev \
    libwebkit2gtk-4.0-dev \
    # udev for device enumeration
    udev \
    libudev-dev \
    # Protobuf
    protobuf-compiler \
    # Networking and testing tools
    curl \
    wget \
    netcat-openbsd \
    iputils-ping \
    dnsutils \
    # JSON processing
    jq \
    # Docker client for docker-in-docker
    docker.io \
    docker-compose \
    # Editor and shell utilities
    vim \
    nano \
    less \
    bc \
    tree \
    htop \
    bash-completion \
    # Debugging tools
    gdb \
    strace \
    valgrind \
    # Additional libraries
    libffi-dev \
    libpcap-dev \
    sudo \
    ca-certificates \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Remove old libtpms installed by swtpm-libs package
RUN DPKG_ARCH=$(dpkg --print-architecture) && \
    case "${DPKG_ARCH}" in \
        amd64) ARCH=x86_64 ;; \
        arm64) ARCH=aarch64 ;; \
        armhf) ARCH=arm ;; \
        *) ARCH=${DPKG_ARCH} ;; \
    esac && \
    rm -f /usr/lib/${ARCH}-linux-gnu/libtpms.so* /lib/${ARCH}-linux-gnu/libtpms.so* 2>/dev/null || true

# Copy built libfido2 v1.17.0 from builder stage (includes library, headers, and tools)
COPY --from=builder /build/libfido2-install/usr /usr

# Copy built libtpms v0.10.1 from builder stage
COPY --from=builder /build/libtpms-install/usr /usr

# Create symlinks for libtpms where SWTPM expects them
RUN DPKG_ARCH=$(dpkg --print-architecture) && \
    case "${DPKG_ARCH}" in \
        amd64) ARCH=x86_64 ;; \
        arm64) ARCH=aarch64 ;; \
        armhf) ARCH=arm ;; \
        *) ARCH=${DPKG_ARCH} ;; \
    esac && \
    mkdir -p /lib/${ARCH}-linux-gnu && \
    ln -sf /usr/lib/libtpms.so.0.10.1 /lib/${ARCH}-linux-gnu/libtpms.so.0.10.1 2>/dev/null || true && \
    ln -sf /lib/${ARCH}-linux-gnu/libtpms.so.0.10.1 /lib/${ARCH}-linux-gnu/libtpms.so.0 2>/dev/null || true && \
    ln -sf /lib/${ARCH}-linux-gnu/libtpms.so.0.10.1 /lib/${ARCH}-linux-gnu/libtpms.so 2>/dev/null || true

# Copy Go protobuf tools from builder
COPY --from=builder /go/bin/protoc-gen-go /go/bin/protoc-gen-go
COPY --from=builder /go/bin/protoc-gen-go-grpc /go/bin/protoc-gen-go-grpc

# Install Node.js 20.x LTS for xKey frontend build (Svelte + Vite + TailwindCSS)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

# Install grpcurl for gRPC testing
RUN GRPCURL_VERSION="1.8.9" && \
    ARCH=$(dpkg --print-architecture) && \
    case "${ARCH}" in \
        amd64) GRPCURL_ARCH="linux_x86_64" ;; \
        arm64) GRPCURL_ARCH="linux_arm64" ;; \
        *) echo "Warning: grpcurl not available for ${ARCH}" ;; \
    esac && \
    if [ -n "${GRPCURL_ARCH}" ]; then \
        curl -sSL "https://github.com/fullstorydev/grpcurl/releases/download/v${GRPCURL_VERSION}/grpcurl_${GRPCURL_VERSION}_${GRPCURL_ARCH}.tar.gz" | \
        tar -xz -C /usr/local/bin grpcurl; \
    fi

# Install additional Go development tools
RUN go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest && \
    go install github.com/go-delve/delve/cmd/dlv@latest && \
    go install golang.org/x/tools/gopls@latest && \
    go install github.com/fatih/gomodifytags@latest && \
    go install github.com/cweill/gotests/gotests@latest && \
    go install github.com/josharian/impl@latest && \
    go install honnef.co/go/tools/cmd/staticcheck@latest

# Update library cache
RUN ldconfig

# Create non-root user for VS Code
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME && \
    useradd --uid $USER_UID --gid $USER_GID -m $USERNAME && \
    echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME && \
    chmod 0440 /etc/sudoers.d/$USERNAME

# Add user to docker group for docker-in-docker
RUN usermod -aG docker $USERNAME 2>/dev/null || true

# Create required directories with proper permissions
RUN mkdir -p /workspace \
    /var/lib/softhsm/tokens \
    /var/lib/swtpm/state \
    /etc/softhsm \
    /etc/xkms \
    /data \
    /var/run/xkms \
    /go/pkg/mod \
    /home/$USERNAME/.cache/go-build && \
    chown -R $USERNAME:$USERNAME /workspace \
    /var/lib/softhsm \
    /var/lib/swtpm \
    /etc/softhsm \
    /etc/xkms \
    /data \
    /var/run/xkms \
    /go \
    /home/$USERNAME

# Setup SoftHSM configuration
RUN echo "directories.tokendir = /var/lib/softhsm/tokens" > /etc/softhsm/softhsm2.conf && \
    echo "objectstore.backend = file" >> /etc/softhsm/softhsm2.conf && \
    echo "log.level = INFO" >> /etc/softhsm/softhsm2.conf

# Ensure OpenSC PKCS#11 library is at expected location
RUN OPENSC_LIB=$(find /usr -name "opensc-pkcs11.so" 2>/dev/null | head -1) && \
    if [ -n "$OPENSC_LIB" ]; then \
        echo "OpenSC PKCS#11 found at: $OPENSC_LIB"; \
    else \
        echo "WARNING: OpenSC PKCS#11 library not found"; \
    fi

# Set environment variables
ENV GOPATH=/go
ENV PATH=/go/bin:/usr/local/go/bin:/usr/local/bin:$PATH
ENV CGO_ENABLED=1
ENV GOCACHE=/home/$USERNAME/.cache/go-build
ENV GOFLAGS="-buildvcs=false"

# PKCS#11 configuration (SoftHSM)
ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf
ENV PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so

# FIDO2 configuration
ENV FIDO2_PIN=123456

# TPM2 configuration
ENV SWTPM_STATE_DIR=/var/lib/swtpm
ENV TPM2TOOLS_TCTI=swtpm:path=/var/lib/swtpm/swtpm-sock

# Switch to non-root user
USER $USERNAME

# Initialize SoftHSM token for testing
# Token: xkms-test, SO PIN: 1234, User PIN: 1234, Slot: 0
RUN softhsm2-util --init-token --slot 0 --label "xkms-test" --so-pin 1234 --pin 1234

WORKDIR /workspace

# Default command
CMD ["sleep", "infinity"]
