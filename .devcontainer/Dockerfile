# go-keychain Development Container
# This container provides ALL dependencies needed for development and testing
# Go Version: 1.25.5 (as specified in go.mod)
#
# Includes:
# - PKCS#11: SoftHSM2, OpenSC (for CanoKey PIV support)
# - TPM2: SWTPM simulator, libtpms v0.10.1, tpm2-tools
# - Quantum: liboqs for quantum-safe cryptography (Dilithium, Kyber)
# - CanoKey: QEMU support for virtual CanoKey testing
# - gRPC: protoc, grpcurl for protocol buffer development
# - Docker: docker-in-docker support for integration tests

# Stage 1: Builder stage - compile dependencies from source
FROM golang:1.25.5-bookworm AS builder

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
    # CMake and Ninja for liboqs
    cmake \
    ninja-build \
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
    # QEMU and USB for CanoKey
    qemu-system-x86 \
    qemu-utils \
    libusb-1.0-0-dev \
    # Protobuf
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Install Go tools for protobuf/gRPC code generation
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Build libtpms v0.10.1 from source to fix TPM_RC_RETRY issue
# See: https://github.com/stefanberger/libtpms/commit/37779b49
WORKDIR /build
RUN git clone https://github.com/stefanberger/libtpms.git && \
    cd libtpms && \
    git checkout v0.10.1 && \
    ./autogen.sh --prefix=/usr --with-openssl --with-tpm2 && \
    make -j$(nproc) && \
    make install DESTDIR=/build/libtpms-install

# Build and install liboqs from source for quantum-safe cryptography
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /build/liboqs && \
    cd /build/liboqs && \
    mkdir build && cd build && \
    cmake -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON .. && \
    ninja && \
    DESTDIR=/build/liboqs-install ninja install

# Clone CanoKey QEMU for virtual device testing
RUN git clone --depth 1 https://github.com/canokeys/canokey-qemu.git /build/canokey-qemu

# Stage 2: Development runtime environment
FROM golang:1.25.5-bookworm

LABEL maintainer="go-keychain"
LABEL description="Development environment for go-keychain with ALL build and test dependencies"

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
    # QEMU for CanoKey virtual device testing
    qemu-system-x86 \
    qemu-utils \
    libusb-1.0-0 \
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

# Copy built liboqs from builder stage
COPY --from=builder /build/liboqs-install/usr/local /usr/local

# Create liboqs-go.pc for the Go bindings
RUN mkdir -p /usr/local/lib/pkgconfig && \
    printf '%s\n' \
        'prefix=/usr/local' \
        'exec_prefix=${prefix}' \
        'libdir=${exec_prefix}/lib' \
        'includedir=${prefix}/include' \
        '' \
        'Name: liboqs-go' \
        'Description: Open Quantum Safe liboqs library for Go bindings' \
        'Version: 0.9.0' \
        'Libs: -L${libdir} -loqs' \
        'Cflags: -I${includedir}' \
    > /usr/local/lib/pkgconfig/liboqs-go.pc

# Copy CanoKey QEMU sources for virtual device testing
COPY --from=builder /build/canokey-qemu /opt/canokey-qemu

# Copy Go protobuf tools from builder
COPY --from=builder /go/bin/protoc-gen-go /go/bin/protoc-gen-go
COPY --from=builder /go/bin/protoc-gen-go-grpc /go/bin/protoc-gen-go-grpc

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
    /etc/keychain \
    /data \
    /var/run/keychain \
    /go/pkg/mod \
    /home/$USERNAME/.cache/go-build && \
    chown -R $USERNAME:$USERNAME /workspace \
    /var/lib/softhsm \
    /var/lib/swtpm \
    /etc/softhsm \
    /etc/keychain \
    /data \
    /var/run/keychain \
    /go \
    /home/$USERNAME

# Setup SoftHSM configuration
RUN echo "directories.tokendir = /var/lib/softhsm/tokens" > /etc/softhsm/softhsm2.conf && \
    echo "objectstore.backend = file" >> /etc/softhsm/softhsm2.conf && \
    echo "log.level = INFO" >> /etc/softhsm/softhsm2.conf

# Set environment variables
ENV GOPATH=/go
ENV PATH=/go/bin:/usr/local/go/bin:/usr/local/bin:$PATH
ENV CGO_ENABLED=1
ENV GOCACHE=/home/$USERNAME/.cache/go-build
ENV GOFLAGS="-buildvcs=false"

# PKCS#11 configuration
ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf
ENV PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so

# TPM2 configuration
ENV SWTPM_STATE_DIR=/var/lib/swtpm
ENV TPM2TOOLS_TCTI=swtpm:path=/var/lib/swtpm/swtpm-sock

# Quantum cryptography (liboqs) configuration
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
ENV CGO_LDFLAGS="-L/usr/local/lib"
ENV CGO_CFLAGS="-I/usr/local/include"

# Switch to non-root user
USER $USERNAME

# Initialize SoftHSM token for testing
RUN softhsm2-util --init-token --slot 0 --label "test-token" --so-pin 1234 --pin 1234

WORKDIR /workspace

# Default command
CMD ["sleep", "infinity"]
