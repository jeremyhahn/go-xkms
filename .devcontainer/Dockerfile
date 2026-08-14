# go-xkms Development Container
# This container provides ALL dependencies needed for development and testing
# Go Version: Latest stable via golang:1.26.1-bookworm (GOTOOLCHAIN=auto)
#
# Includes:
# - PKCS#11: SoftHSM2, OpenSC, pkcs11-provider (for both OpenSSLs)
# - OpenSSH 10.4p1 (source build, private prefix) for PKCS#11 Ed25519 support
# - TPM2: SWTPM simulator, libtpms v0.10.1, tpm2-tools
# - Quantum: pure-Go post-quantum cryptography (ML-DSA, ML-KEM) - no external deps
# - gRPC: protoc, grpcurl for protocol buffer development
# - Docker: docker-in-docker support for integration tests

# Stage 1: Builder stage - compile dependencies from source
FROM golang:1.26.6-bookworm AS builder

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
    perl \
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

# Build pkcs11-provider from source.
#
# OpenSSL 3 deprecated ENGINEs in favour of providers, and a modern deployment
# drives a PKCS#11 module through pkcs11-provider rather than libp11's engine.
# Bookworm does not package it, so it is built here to give the OpenSSL interop
# tests coverage of the interface real OpenSSL 3 callers actually use.
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
        meson ninja-build libssl-dev pkg-config && \
    git clone --depth 1 --branch v0.6 https://github.com/latchset/pkcs11-provider.git && \
    cd pkcs11-provider && \
    meson setup builddir --prefix=/usr --libdir=/usr/lib/x86_64-linux-gnu && \
    meson compile -C builddir && \
    DESTDIR=/build/pkcs11-provider-install meson install -C builddir && \
    rm -rf /var/lib/apt/lists/*

# Build OpenSSL 4.0.1 from source into its own private prefix.
#
# Debian Bookworm only packages OpenSSL 3.0.x, and apt/curl/git/cgo all
# dynamically link against that system libssl3 at /usr/lib. Installing a
# newer OpenSSL system-wide (e.g. into /usr or /usr/local with the default
# libdir) would shadow or conflict with those system libraries and break
# the whole image. Instead this build lives entirely under
# /usr/local/openssl-4.0.1 and is never registered with ldconfig; the
# `openssl` binary carries its own RPATH back to its private libdir so it
# resolves libcrypto.so/libssl.so from that prefix without needing
# LD_LIBRARY_PATH or any system-wide library path change.
WORKDIR /build
RUN DPKG_ARCH=$(dpkg --print-architecture) && \
    case "${DPKG_ARCH}" in \
        amd64) OSSL_TARGET=linux-x86_64 ;; \
        arm64) OSSL_TARGET=linux-aarch64 ;; \
        *) echo "unsupported architecture for OpenSSL 4.0.1 build: ${DPKG_ARCH}" >&2; exit 1 ;; \
    esac && \
    curl -fsSL https://github.com/openssl/openssl/releases/download/openssl-4.0.1/openssl-4.0.1.tar.gz \
        -o openssl-4.0.1.tar.gz && \
    tar xzf openssl-4.0.1.tar.gz && \
    cd openssl-4.0.1 && \
    LDFLAGS="-Wl,-rpath,/usr/local/openssl-4.0.1/lib" \
    ./Configure "${OSSL_TARGET}" shared no-tests \
        --prefix=/usr/local/openssl-4.0.1 \
        --openssldir=/usr/local/openssl-4.0.1/ssl \
        --libdir=lib && \
    make -j$(nproc) && \
    make install_sw install_ssldirs

# Rebuild pkcs11-provider a second time, this time against OpenSSL 4.0.1.
#
# A provider .so is tied to the libcrypto ABI/API version it was compiled
# against (OSSL_provider_init and the core dispatch tables changed between
# 3.x and 4.0), so the OpenSSL-3 provider built above cannot be reused here.
#
# This must be a separate, newer checkout: v0.6 (used above) does not
# compile against OpenSSL 4.0.1 at all. OpenSSL 4.0 made ASN1_STRING/
# ASN1_OCTET_STRING fully opaque (see NEWS.md for openssl-4.0.0), and v0.6
# still pokes at ->data/->length directly in src/objects.c and
# src/encoder.c, which fails to build with "invalid use of incomplete
# typedef". That was fixed upstream in "Use accessors for ASN1_STRING
# values" (https://github.com/latchset/pkcs11-provider/pull/676), released
# in v1.2.0, so the OpenSSL-4.0.1 provider is built from that tag instead.
# PKG_CONFIG_LIBDIR is scoped to only the new OpenSSL's .pc files so meson
# resolves libcrypto/libssl exclusively against 4.0.1 (never the system
# libssl-dev also present in this image) and installs the module straight
# into that OpenSSL's own ossl-modules directory
# (libcrypto.pc's `modulesdir` variable), keeping it fully isolated.
WORKDIR /build
RUN git clone --depth 1 --branch v1.2.0 https://github.com/latchset/pkcs11-provider.git pkcs11-provider-ossl4 && \
    cd pkcs11-provider-ossl4 && \
    PKG_CONFIG_LIBDIR=/usr/local/openssl-4.0.1/lib/pkgconfig \
    meson setup builddir --prefix=/usr/local/openssl-4.0.1 --libdir=lib && \
    meson compile -C builddir && \
    meson install -C builddir

# Build OpenSSH 10.4p1 from source into its own private prefix.
#
# Debian Bookworm ships OpenSSH 9.2p1, whose ssh-pkcs11 layer only handles
# CKK_RSA and CKK_ECDSA. An Ed25519 key that lives on a PKCS#11 token is
# rejected there with "skipping unsupported key type", so `ssh-keygen -D`,
# `ssh-add -s` and public-key auth cannot see it at all. That is a limitation
# of the tool, not of the xkms PKCS#11 module: SoftHSM, the reference PKCS#11
# implementation, produces the identical message for its own Ed25519 key.
# OpenSSH 10.1p1 (2025-10-06) added "ssh(1), ssh-agent(1): support ed25519
# keys hosted on PKCS#11 tokens" - ssh-pkcs11.c now also handles
# CKK_EC_EDWARDS via pkcs11_fetch_ed25519_pubkey()/pkcs11_sign_ed25519().
# 10.4p1 (2026-07-06) is the current portable release and is what is built
# here. The tarball is pinned to the SHA256 published in the upstream
# release notes (https://www.openssh.com/txt/release-10.4).
#
# WHICH OpenSSL: the SYSTEM OpenSSL 3.0.x, deliberately NOT the isolated
# 4.0.1 build above. Reasoning:
#   * Building --without-openssl is not an option. Ed25519 is implemented
#     inside OpenSSH and needs no libcrypto, but the RSA and ECDSA half of
#     PKCS#11 support is compiled only under WITH_OPENSSL, and this image
#     must keep exercising all three key types.
#   * OpenSSH links libfido2 for its built-in U2F/FIDO support (ssh-sk-helper,
#     ssh-keygen -t ed25519-sk), and this image's libfido2 - built from source
#     in this same stage - links the system libcrypto.so.3. Configuring
#     OpenSSH against 4.0.1 makes ld report "warning: libcrypto.so.3, needed
#     by .../libfido2.so, may conflict with libcrypto.so.4" and yields an
#     ssh-sk-helper that maps two libcrypto copies exporting the same symbol
#     names into one address space. Linking the system libcrypto keeps every
#     process single-libcrypto.
#   * The system libcrypto is also what the rest of the image already links
#     (apt/curl/git/cgo, OpenSC/pkcs11-tool, SoftHSM), and libssl3 is
#     guaranteed present in the runtime stage, so these binaries need no
#     RPATH or LD_LIBRARY_PATH of their own.
# The 4.0.1 tree stays exactly what it is today: an isolated build for the
# OpenSSL-4 provider interop tests, untouched by this.
#
# Isolation follows the OpenSSL 4.0.1 precedent above: everything lands under
# /usr/local/openssh-10.4p1 and nothing is written into /usr, /etc or ldconfig.
# `install-nosysconf` is used instead of `install`, so no ssh_config /
# sshd_config / moduli / host keys are ever written outside the prefix -
# Debian's /etc/ssh stays byte-for-byte as the openssh-client package left it.
# sysconfdir still points at /etc/ssh so the new ssh(1) reads the same
# system-wide client config that Debian's ssh(1) reads and that xkms's own
# pkg/ssh/local resolves; it only ever reads that directory, never writes it.
# libfido2 is staged into the builder's /usr first (it is otherwise only
# DESTDIR-installed above) so --with-security-key-builtin can link it, matching
# the built-in FIDO support Debian's openssh-client already provides.
#
# --with-kerberos5 is likewise about parity, not about Kerberos: Debian's
# openssh-client is built with GSSAPI and its /etc/ssh/ssh_config (which this
# build reads, see above) sets "GSSAPIAuthentication yes". Without GSSAPI
# compiled in, every single ssh(1)/scp(1) invocation writes
# `/etc/ssh/ssh_config line 53: Unsupported option "gssapiauthentication"` to
# stderr, which is noise that test harnesses parsing stderr would trip over.
# The Kerberos runtime libraries are already in the runtime image (libcurl and
# git pull in libgssapi_krb5), so this adds no new runtime dependency; only the
# headers are needed here. libkrb5-dev is installed inside this RUN rather than
# in the stage's main apt block so the expensive cached layers above (libfido2,
# libtpms, both pkcs11-providers, OpenSSL 4.0.1) are not invalidated - the same
# thing the pkcs11-provider step above does for meson/ninja.
WORKDIR /build
RUN OPENSSH_VERSION=10.4p1 && \
    OPENSSH_SHA256=ef6026dd2aea8d56059638d5d3262902c892ceba9f88395835e0d06d3fb63238 && \
    apt-get update && apt-get install -y --no-install-recommends libkrb5-dev && \
    rm -rf /var/lib/apt/lists/* && \
    cp -a /build/libfido2-install/usr/. /usr/ && ldconfig && \
    curl -fsSL "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz" \
        -o "openssh-${OPENSSH_VERSION}.tar.gz" && \
    echo "${OPENSSH_SHA256}  openssh-${OPENSSH_VERSION}.tar.gz" | sha256sum -c - && \
    tar xzf "openssh-${OPENSSH_VERSION}.tar.gz" && \
    cd "openssh-${OPENSSH_VERSION}" && \
    ./configure \
        --prefix="/usr/local/openssh-${OPENSSH_VERSION}" \
        --sysconfdir=/etc/ssh \
        --with-privsep-path="/usr/local/openssh-${OPENSSH_VERSION}/var/empty" \
        --with-privsep-user=nobody \
        --enable-pkcs11 \
        --with-security-key-builtin \
        --with-kerberos5 \
        --with-zlib \
        --with-ssl-dir=/usr && \
    if ! grep -q '^#define ENABLE_PKCS11' config.h; then \
        echo "FATAL: OpenSSH configured without PKCS#11 support" >&2; exit 1; \
    fi && \
    if ! grep -q '^#define ENABLE_SK' config.h; then \
        echo "FATAL: OpenSSH configured without U2F/FIDO support" >&2; exit 1; \
    fi && \
    if ! grep -q '^#define GSSAPI' config.h; then \
        echo "FATAL: OpenSSH configured without GSSAPI support" >&2; exit 1; \
    fi && \
    make -j$(nproc) && \
    make install-nosysconf

# Stage 2: Development runtime environment
FROM golang:1.26.6-bookworm

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
    # SSL/TLS libraries. Debian's system OpenSSL 3.0.x (`openssl` CLI +
    # libssl3) is deliberately kept installed here: it is what apt, curl,
    # git and cgo already link against, and it is the only OpenSSL that
    # can still load the deprecated libp11 ENGINE (see the pkcs11-engine
    # comment below). OpenSSL 4.0.1 is layered in separately below from
    # /usr/local/openssl-4.0.1 (built in the builder stage) and put ahead
    # on PATH, so the two installs never collide: the system package keeps
    # apt/curl/git/cgo working exactly as before, and `openssl` on PATH
    # resolves to 4.0.1 for everything else.
    openssl \
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
    # OpenSSL pkcs11 ENGINE (libp11) - required by the PKCS#11 module's
    # ENGINE-based OpenSSL interop tests, which now fail rather than skip
    # when it is absent. OpenSSL 4.0 removed ENGINE support entirely (see
    # https://github.com/openssl/openssl/blob/openssl-4.0.1/NEWS.md and
    # include/openssl/engine.h in that tag: "Engine support is gone.
    # Definitions here are provided for source code compatibility only.")
    # so this package can only ever load into the system OpenSSL 3.0.x
    # above, never into the 4.0.1 build. It is intentionally NOT rebuilt
    # against 4.0.1 - that is not possible, only worked around by porting
    # the tests to pkcs11-provider, which is a separate migration.
    libengine-pkcs11-openssl \
    # Debian's openssh-client (9.2p1) is deliberately kept installed: it owns
    # /etc/ssh/ssh_config, ssh-copy-id and the ssh man pages, and it is the
    # fallback still reachable at /usr/bin/ssh*. It is NOT what the PKCS#11
    # interop tests run, though - OpenSSH 10.4p1 is layered in below from
    # /usr/local/openssh-10.4p1 (built in the builder stage) and put ahead on
    # PATH, because only 10.1p1+ can use Ed25519 keys hosted on a PKCS#11
    # token. See the OpenSSH build comment in the builder stage.
    openssh-client \
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
    # Chromium, and with it the browser runtime libraries Playwright needs,
    # for the WebAuthn RP ceremony suite (test/integration/webauthn-browser)
    chromium \
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

# Copy pkcs11-provider so the OpenSSL 3 interop tests can drive the module
# through a provider (the interface that replaced ENGINEs) as well as libp11.
COPY --from=builder /build/pkcs11-provider-install/usr /usr

# Copy the private OpenSSL 4.0.1 install (built in the builder stage, with
# its own RPATH back to /usr/local/openssl-4.0.1/lib) plus the pkcs11-provider
# module that was rebuilt against it, straight into that prefix. Nothing
# here touches /usr/lib or the system libssl3/libssl-dev installed above.
COPY --from=builder /usr/local/openssl-4.0.1 /usr/local/openssl-4.0.1

# Sample config that activates the pkcs11-provider under OpenSSL 4.0.1 for
# manual/test use via OPENSSL_CONF (see the file for usage). Placed
# alongside that OpenSSL's own ssl dir, not baked in as the container-wide
# default so unrelated `openssl` invocations keep OpenSSL's normal
# default-only provider behavior.
COPY openssl-pkcs11.cnf /usr/local/openssl-4.0.1/ssl/openssl-pkcs11.cnf

# Copy the private OpenSSH 10.4p1 install (built in the builder stage). Like
# the OpenSSL 4.0.1 tree it is entirely self-contained: its binaries link the
# system libcrypto.so.3/libz/libfido2 already installed above, and OpenSSH
# resolves its own helpers (ssh-pkcs11-helper, ssh-sk-helper, ssh-askpass) by
# the absolute libexec path compiled into them, so nothing here depends on
# ldconfig, LD_LIBRARY_PATH or PATH. Debian's openssh-client under /usr/bin
# and its /etc/ssh config are left untouched.
COPY --from=builder /usr/local/openssh-10.4p1 /usr/local/openssh-10.4p1

# Put the OpenSSH 10.4p1 client tools ahead of Debian's on PATH. The ENV PATH
# below already covers this for every process the image starts, but login
# shells re-derive PATH from /etc/profile, which drops it; /usr/local/bin is on
# that default PATH ahead of /usr/bin, so these symlinks make the resolution
# uniform for login shells, sudo's secure_path and anything that execs with a
# default PATH. Debian's binaries remain addressable at /usr/bin/ssh*.
RUN for ossh_bin in scp sftp ssh ssh-add ssh-agent ssh-keygen ssh-keyscan; do \
        ln -sf "/usr/local/openssh-10.4p1/bin/${ossh_bin}" "/usr/local/bin/${ossh_bin}"; \
    done

# Convenience symlinks so tests/tooling can request a specific OpenSSL by
# name regardless of PATH order: openssl-4.0.1 is the new isolated build
# (also the default `openssl` on PATH, see PATH below); openssl-3 is
# Debian's system OpenSSL 3.0.x, the only one that can load the deprecated
# libp11 ENGINE.
RUN ln -sf /usr/local/openssl-4.0.1/bin/openssl /usr/local/bin/openssl-4.0.1 && \
    ln -sf /usr/bin/openssl /usr/local/bin/openssl-3

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
# /usr/local/openssl-4.0.1/bin leads PATH so `openssl` resolves to 4.0.1 by
# default everywhere in the image. This only changes command *resolution*;
# it does not touch any shared library search path, so it cannot affect
# apt/curl/git/cgo, which keep linking against the system libssl3 installed
# above regardless of PATH. The 4.0.1 binaries carry their own RPATH (set at
# build time) back to /usr/local/openssl-4.0.1/lib, so no LD_LIBRARY_PATH or
# ldconfig registration is needed for them either. Use `openssl-3` /
# `openssl-4.0.1` (symlinks installed above) to pick a specific build.
#
# /usr/local/openssh-10.4p1/bin leads for the same reason: `ssh`, `ssh-keygen`,
# `ssh-agent` and `ssh-add` must resolve to the 10.4p1 build, which is the only
# one that can use Ed25519 keys hosted on a PKCS#11 token. Debian's 9.2p1
# openssh-client is still installed and reachable at /usr/bin/ssh*.
ENV PATH=/usr/local/openssh-10.4p1/bin:/usr/local/openssl-4.0.1/bin:/go/bin:/usr/local/go/bin:/usr/local/bin:$PATH
ENV CGO_ENABLED=1
ENV GOCACHE=/home/$USERNAME/.cache/go-build
ENV GOFLAGS="-buildvcs=false"

# Login shells (bash -l, and the zsh the devcontainer feature installs) source
# /etc/profile, which unconditionally *overwrites* PATH with Debian's default.
# That silently undoes the ENV PATH above, so an interactive `openssl version`
# reports the system 3.0.x and `go` is not found at all - while the same
# command through `bash -c` (what the Makefile uses) sees 10.4p1/4.0.1. Pin the
# ordering again from /etc/profile.d, which is sourced after PATH is reset, so
# both entry paths agree on which toolchain is in front.
RUN printf '%s\n' \
    'PATH=/usr/local/openssh-10.4p1/bin:/usr/local/openssl-4.0.1/bin:/go/bin:/usr/local/go/bin:$PATH' \
    'export PATH' \
    > /etc/profile.d/10-xkms-toolchain.sh

# CA trust for the isolated OpenSSL 4.0.1 build - reuses the same system CA
# bundle apt/curl/git already trust, it does not change what any of those
# tools trust since it is the same file they already default to.
ENV SSL_CERT_DIR=/etc/ssl/certs
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

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
