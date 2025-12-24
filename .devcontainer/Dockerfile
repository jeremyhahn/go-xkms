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
    # CMake and Ninja for liboqs and CanoKey
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
    # QEMU build dependencies for CanoKey support
    python3 \
    python3-pip \
    python3-venv \
    libglib2.0-dev \
    libfdt-dev \
    libpixman-1-dev \
    zlib1g-dev \
    libgtk-3-dev \
    libsdl2-dev \
    libspice-server-dev \
    libusbredirparser-dev \
    libcap-ng-dev \
    libattr1-dev \
    libseccomp-dev \
    libaio-dev \
    libcurl4-gnutls-dev \
    libnuma-dev \
    libepoxy-dev \
    libgbm-dev \
    libdrm-dev \
    libvirglrenderer-dev \
    libslirp-dev \
    flex \
    bison \
    curl \
    xz-utils \
    # FIDO2/WebAuthn support
    libfido2-dev \
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

# CanoKey QEMU build is disabled by default to save CI disk space (~2GB)
# Set BUILD_CANOKEY_QEMU=true to enable (requires significant disk space and build time)
ARG BUILD_CANOKEY_QEMU=false
ARG QEMU_VERSION=8.2.0

# Build CanoKey QEMU only if explicitly enabled
RUN mkdir -p /build/qemu-install/usr/local/bin && \
    if [ "${BUILD_CANOKEY_QEMU}" = "true" ]; then \
        echo "Building CanoKey QEMU (BUILD_CANOKEY_QEMU=true)..." && \
        git clone --recursive https://github.com/canokeys/canokey-qemu.git /build/canokey-qemu && \
        cd /build/canokey-qemu && \
        mkdir build && cd build && \
        cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local && \
        make -j$(nproc) && \
        make install && \
        ldconfig && \
        export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH && \
        cd /build && \
        curl -sSL "https://download.qemu.org/qemu-${QEMU_VERSION}.tar.xz" -o qemu.tar.xz && \
        tar xf qemu.tar.xz && \
        cd qemu-${QEMU_VERSION} && \
        ./configure \
            --prefix=/usr/local \
            --target-list=x86_64-softmmu \
            --enable-kvm \
            --enable-canokey \
            --enable-slirp \
            --enable-usb-redir \
            --enable-libusb \
            --enable-virtfs \
            --enable-spice \
            --enable-gtk \
            --enable-sdl \
            --enable-opengl \
            --enable-virglrenderer \
            --disable-docs && \
        make -j$(nproc) && \
        cp build/qemu-system-x86_64 /build/qemu-install/usr/local/bin/qemu-system-x86_64-canokey && \
        rm -rf /build/qemu-${QEMU_VERSION} /build/qemu.tar.xz /build/canokey-qemu; \
    else \
        echo "Skipping CanoKey QEMU build (BUILD_CANOKEY_QEMU=${BUILD_CANOKEY_QEMU})"; \
        touch /build/qemu-install/usr/local/bin/.qemu-canokey-not-built; \
    fi

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
    # FIDO2/WebAuthn support
    libfido2-1 \
    libfido2-dev \
    fido2-tools \
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

# Copy built libcanokey and QEMU binary from builder stage (optional - may not exist if build failed)
COPY --from=builder /build/qemu-install/usr/local/bin/ /usr/local/bin/

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

# Verify CanoKey QEMU installation (optional - may not be available)
RUN echo "=== CanoKey QEMU Verification ===" && \
    echo "Standard QEMU: $(qemu-system-x86_64 --version 2>/dev/null | head -1 || echo 'not installed')" && \
    if [ -x /usr/local/bin/qemu-system-x86_64-canokey ]; then \
        echo "CanoKey QEMU: $(/usr/local/bin/qemu-system-x86_64-canokey --version | head -1)"; \
    else \
        echo "CanoKey QEMU: not available (optional feature)"; \
    fi && \
    echo "libcanokey: $(ldconfig -p | grep canokey || echo 'not installed (optional)')" && \
    echo "================================="

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

# Ensure OpenSC PKCS#11 library is at expected location
RUN OPENSC_LIB=$(find /usr -name "opensc-pkcs11.so" 2>/dev/null | head -1) && \
    if [ -n "$OPENSC_LIB" ]; then \
        echo "OpenSC PKCS#11 found at: $OPENSC_LIB"; \
    else \
        echo "WARNING: OpenSC PKCS#11 library not found"; \
    fi

# Create CanoKey directories
RUN mkdir -p /var/lib/canokey && \
    chown -R $USERNAME:$USERNAME /var/lib/canokey

# Set environment variables
ENV GOPATH=/go
ENV PATH=/go/bin:/usr/local/go/bin:/usr/local/bin:$PATH
ENV CGO_ENABLED=1
ENV GOCACHE=/home/$USERNAME/.cache/go-build
ENV GOFLAGS="-buildvcs=false"

# PKCS#11 configuration (SoftHSM)
ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf
ENV PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so

# CanoKey PKCS#11 configuration (OpenSC)
ENV CANOKEY_PKCS11_LIBRARY=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
ENV CANOKEY_PIN=123456
ENV CANOKEY_SOPIN=12345678

# FIDO2/CanoKey QEMU configuration
ENV CANOKEY_QEMU=/var/lib/canokey/canokey.sock
ENV FIDO2_DEVICE_PATH=/var/lib/canokey/canokey.sock
ENV FIDO2_PIN=123456

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
