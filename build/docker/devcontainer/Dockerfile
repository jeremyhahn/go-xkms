# syntax=docker/dockerfile:1
#
# go-xkms devcontainer image (handbook devcontainer.md, ci-standard.md).
#
# One Dockerfile, built from the repository root, serves every place go-xkms
# code is built or tested:
#   toolchain    -- the CI stages: `make build`, `make test`, `make security`,
#                   `make deps-check` and the go-xkms jobs (ci.yml), run through
#                   scripts/in-toolchain-image.sh or `make docker-run`.
#   integration  -- the hardened integration service (compose.yaml).
#   devcontainer -- the interactive harness compose.yaml and devcontainer.json
#                   start, with its swtpm/SoftHSM/softfido sidecars.
#
# Every version and download checksum comes from scripts/tool-pins.sh, which
# the Makefile also includes. GO_IMAGE has no default on purpose: build through
# `make docker-build`, which passes the pinned digest.
#
# Includes:
# - PKCS#11: SoftHSM 2.7.0, OpenSC, pkcs11-provider (for both OpenSSLs)
# - OpenSSH (source build, private prefix) for PKCS#11 Ed25519 support
# - TPM2: swtpm simulator, libtpms, tpm2-tools
# - FIDO2: libfido2 from its release tarball
# - gRPC: protoc, grpcurl
# - The gate tools: golangci-lint, actionlint, shellcheck, gosec, govulncheck, trivy
ARG GO_IMAGE
# GO_BUILD_PROXY is the GOPROXY of the tools and modules stages. The Makefile
# passes the caller's GOPROXY (CI exports the fleet's module proxy first); this
# default applies only when none is set. Checksum verification stays on.
ARG GO_BUILD_PROXY=https://proxy.golang.org,direct

# ---------------------------------------------------------------------------
# tools: the pinned gate tools and release binaries, collected under /out.
# ---------------------------------------------------------------------------
FROM ${GO_IMAGE} AS tools
ARG GO_BUILD_PROXY
ARG TARGETARCH
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOPROXY=${GO_BUILD_PROXY} GOBIN=/out
# apt retries transient fetch errors: one "Network is unreachable" reaching
# deb.debian.org reddened CI (run 58741). Repeated per FROM ${GO_IMAGE} stage.
RUN printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\n' > /etc/apt/apt.conf.d/80-retries
RUN apt-get update && apt-get install -y --no-install-recommends xz-utils && \
    rm -rf /var/lib/apt/lists/*
COPY scripts/tool-pins.sh /tmp/tool-pins.sh
RUN . /tmp/tool-pins.sh && \
    go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_VERSION} && \
    go install github.com/rhysd/actionlint/cmd/actionlint@${ACTIONLINT_VERSION} && \
    go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION} && \
    go install google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOBUF_GO_VERSION} && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@${PROTOC_GEN_GO_GRPC_VERSION}
# gosec is built against XTOOLS_VERSION: the x/tools its own go.mod names
# cannot read the export data Go 1.27 writes, so every import fails to
# type-check. A throwaway module carries the upgraded requirement. The
# command package is named in go get, not the module root, so go.sum gets
# every module cmd/gosec imports.
RUN . /tmp/tool-pins.sh && \
    mkdir /tmp/gosec && cd /tmp/gosec && go mod init gosec-build && \
    go get github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION} golang.org/x/tools@${XTOOLS_VERSION} && \
    go install github.com/securego/gosec/v2/cmd/gosec && \
    rm -rf /tmp/gosec
# Interactive conveniences, kept out of /out so only the devcontainer carries them.
RUN . /tmp/tool-pins.sh && \
    GOBIN=/devout go install github.com/go-delve/delve/cmd/dlv@${DELVE_VERSION} && \
    GOBIN=/devout go install golang.org/x/tools/gopls@${GOPLS_VERSION} && \
    GOBIN=/devout go install github.com/fatih/gomodifytags@${GOMODIFYTAGS_VERSION} && \
    GOBIN=/devout go install github.com/cweill/gotests/gotests@${GOTESTS_VERSION} && \
    GOBIN=/devout go install github.com/josharian/impl@${IMPL_VERSION} && \
    GOBIN=/devout go install honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}
# Release archives, each checked against its pinned SHA-256 before unpacking.
RUN . /tmp/tool-pins.sh && \
    case "${TARGETARCH}" in \
        amd64) trivy_arch=64bit; trivy_sum=${TRIVY_SHA256_LINUX_AMD64}; \
               grpcurl_arch=linux_x86_64; grpcurl_sum=${GRPCURL_SHA256_LINUX_AMD64}; \
               node_arch=linux-x64; node_sum=${NODE_SHA256_LINUX_AMD64}; \
               shellcheck_arch=x86_64; shellcheck_sum=${SHELLCHECK_SHA256_LINUX_AMD64} ;; \
        arm64) trivy_arch=ARM64; trivy_sum=${TRIVY_SHA256_LINUX_ARM64}; \
               grpcurl_arch=linux_arm64; grpcurl_sum=${GRPCURL_SHA256_LINUX_ARM64}; \
               node_arch=linux-arm64; node_sum=${NODE_SHA256_LINUX_ARM64}; \
               shellcheck_arch=aarch64; shellcheck_sum=${SHELLCHECK_SHA256_LINUX_ARM64} ;; \
        *) echo "no tool pins for architecture ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    cd /tmp && \
    trivy_tgz="trivy_${TRIVY_VERSION#v}_Linux-${trivy_arch}.tar.gz" && \
    curl -fsSLo "${trivy_tgz}" "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/${trivy_tgz}" && \
    echo "${trivy_sum}  ${trivy_tgz}" | sha256sum -c - && \
    tar -xzf "${trivy_tgz}" -C /out trivy && \
    grpcurl_tgz="grpcurl_${GRPCURL_VERSION}_${grpcurl_arch}.tar.gz" && \
    curl -fsSLo "${grpcurl_tgz}" "https://github.com/fullstorydev/grpcurl/releases/download/v${GRPCURL_VERSION}/${grpcurl_tgz}" && \
    echo "${grpcurl_sum}  ${grpcurl_tgz}" | sha256sum -c - && \
    tar -xzf "${grpcurl_tgz}" -C /out grpcurl && \
    node_txz="node-${NODE_VERSION}-${node_arch}.tar.xz" && \
    curl -fsSLo "${node_txz}" "https://nodejs.org/dist/${NODE_VERSION}/${node_txz}" && \
    echo "${node_sum}  ${node_txz}" | sha256sum -c - && \
    mkdir -p /opt/node && tar -xJf "${node_txz}" -C /opt/node --strip-components=1 && \
    shellcheck_txz="shellcheck-${SHELLCHECK_VERSION}.linux.${shellcheck_arch}.tar.xz" && \
    curl -fsSLo "${shellcheck_txz}" "https://github.com/koalaman/shellcheck/releases/download/${SHELLCHECK_VERSION}/${shellcheck_txz}" && \
    echo "${shellcheck_sum}  ${shellcheck_txz}" | sha256sum -c - && \
    tar -xJf "${shellcheck_txz}" -C /out --strip-components=1 "shellcheck-${SHELLCHECK_VERSION}/shellcheck" && \
    rm -f "${trivy_tgz}" "${grpcurl_tgz}" "${node_txz}" "${shellcheck_txz}"

# ---------------------------------------------------------------------------
# native: the libraries and tools built from source, staged for COPY.
# ---------------------------------------------------------------------------
FROM ${GO_IMAGE} AS native
ENV GOTOOLCHAIN=local DEBIAN_FRONTEND=noninteractive
# apt retries transient fetch errors (see the tools stage).
RUN printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\n' > /etc/apt/apt.conf.d/80-retries
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
    # pkcs11-provider builds with meson
    meson \
    ninja-build \
    # OpenSSH's GSSAPI support (see the OpenSSH step)
    libkrb5-dev \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/tool-pins.sh /tmp/tool-pins.sh
WORKDIR /build

# SoftHSM 2.7.0 from its pinned, checksum-verified release, replacing Debian's
# 2.6.1: that release answers an AES-GCM tag mismatch with the ambiguous
# CKR_GENERAL_ERROR, so PKCS#11 tamper could not be classified as
# types.ErrSealedDataAuthentication (go-xkms#1418). The script is the single
# pin (scripts/build-softhsm.sh); this build's context is the repository root.
COPY scripts/build-softhsm.sh /build/build-softhsm.sh
RUN DESTDIR=/build/softhsm-install sh /build/build-softhsm.sh

# libfido2 from its release tarball: Debian ships 1.12.0, which lacks the UHID
# virtual-device product name (HID_NAME fallback) softfido relies on.
RUN . /tmp/tool-pins.sh && \
    tgz="libfido2-${LIBFIDO2_VERSION}.tar.gz" && \
    curl -fsSLo "${tgz}" "https://developers.yubico.com/libfido2/Releases/${tgz}" && \
    echo "${LIBFIDO2_SHA256}  ${tgz}" | sha256sum -c - && \
    tar -xzf "${tgz}" && cd "libfido2-${LIBFIDO2_VERSION}" && \
    mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr .. && \
    make -j"$(nproc)" && \
    make install DESTDIR=/build/libfido2-install

# libtpms from its release tag, to fix the TPM_RC_RETRY issue
# (https://github.com/stefanberger/libtpms/commit/37779b49).
RUN . /tmp/tool-pins.sh && \
    tgz="libtpms-${LIBTPMS_VERSION}.tar.gz" && \
    curl -fsSLo "${tgz}" "https://github.com/stefanberger/libtpms/archive/refs/tags/v${LIBTPMS_VERSION}.tar.gz" && \
    echo "${LIBTPMS_SHA256}  ${tgz}" | sha256sum -c - && \
    tar -xzf "${tgz}" && cd "libtpms-${LIBTPMS_VERSION}" && \
    ./autogen.sh --prefix=/usr --with-openssl --with-tpm2 && \
    make -j"$(nproc)" && \
    make install DESTDIR=/build/libtpms-install

# pkcs11-provider against the system OpenSSL 3.
#
# OpenSSL 3 deprecated ENGINEs in favour of providers, and a modern deployment
# drives a PKCS#11 module through pkcs11-provider rather than libp11's engine.
# Bookworm does not package it, so it is built here to give the OpenSSL interop
# tests coverage of the interface real OpenSSL 3 callers actually use.
RUN . /tmp/tool-pins.sh && \
    v=${PKCS11_PROVIDER_OSSL3_VERSION} && txz="pkcs11-provider-${v}.tar.xz" && \
    curl -fsSLo "${txz}" "https://github.com/latchset/pkcs11-provider/releases/download/v${v}/${txz}" && \
    echo "${PKCS11_PROVIDER_OSSL3_SHA256}  ${txz}" | sha256sum -c - && \
    tar -xJf "${txz}" && cd "pkcs11-provider-${v}" && \
    meson setup builddir --prefix=/usr --libdir="/usr/lib/$(gcc -dumpmachine)" && \
    meson compile -C builddir && \
    DESTDIR=/build/pkcs11-provider-install meson install -C builddir

# OpenSSL 4 from source into its own private prefix.
#
# Debian Bookworm only packages OpenSSL 3.0.x, and apt/curl/git/cgo all
# dynamically link against that system libssl3 at /usr/lib. Installing a
# newer OpenSSL system-wide would shadow or conflict with those libraries and
# break the whole image. Instead this build lives entirely under
# /usr/local/openssl-<version> and is never registered with ldconfig; the
# `openssl` binary carries its own RPATH back to its private libdir.
RUN . /tmp/tool-pins.sh && \
    case "$(dpkg --print-architecture)" in \
        amd64) ossl_target=linux-x86_64 ;; \
        arm64) ossl_target=linux-aarch64 ;; \
        *) echo "unsupported architecture for the OpenSSL build" >&2; exit 1 ;; \
    esac && \
    prefix="/usr/local/openssl-${OPENSSL_VERSION}" && \
    tgz="openssl-${OPENSSL_VERSION}.tar.gz" && \
    curl -fsSLo "${tgz}" "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/${tgz}" && \
    echo "${OPENSSL_SHA256}  ${tgz}" | sha256sum -c - && \
    tar -xzf "${tgz}" && cd "openssl-${OPENSSL_VERSION}" && \
    LDFLAGS="-Wl,-rpath,${prefix}/lib" \
    ./Configure "${ossl_target}" shared no-tests \
        --prefix="${prefix}" \
        --openssldir="${prefix}/ssl" \
        --libdir=lib && \
    make -j"$(nproc)" && \
    make install_sw install_ssldirs

# pkcs11-provider a second time, against OpenSSL 4.
#
# A provider .so is tied to the libcrypto ABI it was compiled against, so the
# OpenSSL 3 provider above cannot be reused. The older release does not compile
# against OpenSSL 4 (ASN1_STRING became opaque); "Use accessors for ASN1_STRING
# values" (https://github.com/latchset/pkcs11-provider/pull/676) fixed that in
# v1.2.0. PKG_CONFIG_LIBDIR is scoped to the new OpenSSL's .pc files so meson
# resolves libcrypto/libssl exclusively against it and installs the module into
# that OpenSSL's own ossl-modules directory.
RUN . /tmp/tool-pins.sh && \
    v=${PKCS11_PROVIDER_OSSL4_VERSION} && txz="pkcs11-provider-${v}.tar.xz" && \
    curl -fsSLo "${txz}" "https://github.com/latchset/pkcs11-provider/releases/download/v${v}/${txz}" && \
    echo "${PKCS11_PROVIDER_OSSL4_SHA256}  ${txz}" | sha256sum -c - && \
    mkdir pkcs11-provider-ossl4 && tar -xJf "${txz}" -C pkcs11-provider-ossl4 --strip-components=1 && \
    cd pkcs11-provider-ossl4 && \
    PKG_CONFIG_LIBDIR="/usr/local/openssl-${OPENSSL_VERSION}/lib/pkgconfig" \
    meson setup builddir --prefix="/usr/local/openssl-${OPENSSL_VERSION}" --libdir=lib && \
    meson compile -C builddir && \
    meson install -C builddir

# OpenSSH from source into its own private prefix.
#
# Debian Bookworm ships OpenSSH 9.2p1, whose ssh-pkcs11 layer only handles
# CKK_RSA and CKK_ECDSA; an Ed25519 key on a PKCS#11 token is skipped as an
# "unsupported key type". OpenSSH 10.1p1 added Ed25519 keys hosted on PKCS#11
# tokens. It links the SYSTEM OpenSSL 3, not the isolated OpenSSL 4 build:
# libfido2 (linked for the built-in FIDO support) links the system libcrypto,
# and two libcrypto copies in one process would conflict. Everything lands
# under /usr/local/openssh-<version>; `install-nosysconf` writes nothing to
# /etc, and sysconfdir stays /etc/ssh so it reads Debian's client config.
# --with-kerberos5 matches Debian's GSSAPI build, without which every ssh(1)
# run warns about the "GSSAPIAuthentication" line in /etc/ssh/ssh_config.
RUN . /tmp/tool-pins.sh && \
    prefix="/usr/local/openssh-${OPENSSH_VERSION}" && \
    cp -a /build/libfido2-install/usr/. /usr/ && ldconfig && \
    tgz="openssh-${OPENSSH_VERSION}.tar.gz" && \
    curl -fsSLo "${tgz}" "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/${tgz}" && \
    echo "${OPENSSH_SHA256}  ${tgz}" | sha256sum -c - && \
    tar -xzf "${tgz}" && cd "openssh-${OPENSSH_VERSION}" && \
    ./configure \
        --prefix="${prefix}" \
        --sysconfdir=/etc/ssh \
        --with-privsep-path="${prefix}/var/empty" \
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
    make -j"$(nproc)" && \
    make install-nosysconf

# ---------------------------------------------------------------------------
# modules: every module's build list, downloaded once and verified.
# ---------------------------------------------------------------------------
FROM ${GO_IMAGE} AS modules
ARG GO_BUILD_PROXY
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOMODCACHE=/gomodcache GOPROXY=${GO_BUILD_PROXY}
WORKDIR /src
# The root module, sdk/go, xkey and web/desktop replace each other locally,
# so all four go.mod/go.sum pairs are needed to resolve any one of them.
COPY go.mod go.sum ./
COPY sdk/go/go.mod sdk/go/go.sum ./sdk/go/
COPY xkey/go.mod xkey/go.sum ./xkey/
COPY web/desktop/go.mod web/desktop/go.sum ./web/desktop/
# In-house modules resolve from forge tags with the read-only fetch token in
# the gomodauth BuildKit secret (dependency-resolution.md §6); without it
# everything resolves through GO_BUILD_PROXY. Besides each build list this fetches the
# arduino-generic source scripts/build-agsim.sh compiles and the wails CLI
# `make check-wailsjs` runs, so the test stage needs no network for either.
RUN --mount=type=secret,id=gomodauth \
    if [ -s /run/secrets/gomodauth ]; then \
        set -a; . /run/secrets/gomodauth; set +a; \
        echo "modules: forge credentials loaded from the gomodauth secret"; \
    else \
        echo "modules: no gomodauth secret; resolving through GO_BUILD_PROXY"; \
    fi && \
    for m in . sdk/go xkey web/desktop; do (cd "$m" && go mod download) || exit 1; done && \
    agsim_version=$(go list -m -f '{{.Version}}' github.com/jeremyhahn/arduino-generic/sdk/go) && \
    go mod download "github.com/jeremyhahn/arduino-generic@${agsim_version}" && \
    wails_version=$(cd xkey && go list -m -f '{{.Version}}' github.com/wailsapp/wails/v2) && \
    GOBIN=/tmp/wails go install "github.com/wailsapp/wails/v2/cmd/wails@${wails_version}" && \
    rm -rf /tmp/wails
RUN for m in . sdk/go xkey web/desktop; do (cd "$m" && go mod verify) || exit 1; done

# ---------------------------------------------------------------------------
# base: the Go toolchain, every native library and the verified module cache.
# ---------------------------------------------------------------------------
FROM ${GO_IMAGE} AS base
ENV DEBIAN_FRONTEND=noninteractive
# apt retries transient fetch errors (see the tools stage); toolchain and
# devcontainer, built FROM base, inherit the setting.
RUN printf 'Acquire::Retries "5";\nAcquire::http::Timeout "30";\n' > /etc/apt/apt.conf.d/80-retries
# The upgrade takes the Debian security updates the pinned Go image predates
# (linux-libc-dev among them): the integration image built on this stage is
# gated by `trivy image --ignore-unfixed` (ci.yml).
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    # Core build tools (needed for CGO)
    build-essential \
    gcc \
    g++ \
    make \
    pkg-config \
    git \
    # SSL/TLS libraries. Debian's system OpenSSL 3.0.x (`openssl` CLI +
    # libssl3) stays installed: apt, curl, git and cgo link against it, and it
    # is the only OpenSSL that can still load the deprecated libp11 ENGINE.
    # OpenSSL 4 is layered in separately from its private prefix and put ahead
    # on PATH, so the two installs never collide.
    openssl \
    libssl3 \
    libssl-dev \
    libgnutls30 \
    libtasn1-6 \
    # PKCS#11 and smart card (SoftHSM is built in the native stage)
    opensc \
    opensc-pkcs11 \
    pcscd \
    libpcsclite1 \
    libpcsclite-dev \
    libp11-kit-dev \
    # D-Bus and freedesktop Secret Service (xkey secret-service, go-xkms#723):
    # dbus-run-session wraps integration-test-secretservice; libsecret-1-dev
    # and libglib2.0-dev build git-credential-libsecret below.
    dbus \
    libsecret-tools \
    libsecret-1-dev \
    libglib2.0-dev \
    # OpenSSL pkcs11 ENGINE (libp11) for the PKCS#11 module's ENGINE interop
    # tests. OpenSSL 4 removed ENGINE support, so it loads only into the
    # system OpenSSL 3.
    libengine-pkcs11-openssl \
    # Debian's openssh-client owns /etc/ssh/ssh_config and stays the fallback
    # at /usr/bin/ssh*; the PKCS#11 interop tests run the source build.
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
    # dolthub/go-icu-regex (transitively via go-qrdb) needs this cgo header
    libicu-dev \
    # FIDO2/WebAuthn runtime dependencies (libfido2 is built in the native stage)
    libcbor0.8 \
    # Wails v2 GUI dependencies: WebKit2GTK 4.0 for the xkey build, 4.1 for
    # the acme-client GUI build (webkit2_41)
    libgtk-3-dev \
    libwebkit2gtk-4.0-dev \
    libwebkit2gtk-4.1-dev \
    # xkey BLE support (tinygo bluetooth)
    libbluetooth-dev \
    # udev for device enumeration
    udev \
    libudev-dev \
    # Protobuf
    protobuf-compiler \
    # Fetching, archives, JSON
    curl \
    ca-certificates \
    xz-utils \
    unzip \
    jq \
    && rm -rf /var/lib/apt/lists/*

# git-credential-libsecret from git's own contrib source: Debian does not ship
# a compiled binary for it, and the xkey secret-service tests use it.
RUN make -C /usr/share/doc/git/contrib/credential/libsecret && \
    install -m 0755 /usr/share/doc/git/contrib/credential/libsecret/git-credential-libsecret /usr/local/bin/git-credential-libsecret && \
    make -C /usr/share/doc/git/contrib/credential/libsecret clean

# Remove the old libtpms the swtpm package pulled in; the native build replaces it.
RUN rm -f "/usr/lib/$(gcc -dumpmachine)"/libtpms.so* "/lib/$(gcc -dumpmachine)"/libtpms.so*

COPY --from=native /build/libfido2-install/usr /usr
COPY --from=native /build/libtpms-install/usr /usr
# SoftHSM 2.7.0: /usr/lib/softhsm/libsofthsm2.so, the softhsm2-* utilities and
# /etc/softhsm (Debian's paths).
COPY --from=native /build/softhsm-install/ /
COPY --from=native /build/pkcs11-provider-install/usr /usr
# The private OpenSSL 4 install with the pkcs11-provider rebuilt against it.
COPY --from=native /usr/local/openssl-4.0.1 /usr/local/openssl-4.0.1
# Sample config that activates the pkcs11-provider under OpenSSL 4 via
# OPENSSL_CONF; not the container-wide default.
COPY build/docker/devcontainer/openssl-pkcs11.cnf /usr/local/openssl-4.0.1/ssl/openssl-pkcs11.cnf
# The private OpenSSH install; its helpers resolve by absolute libexec path.
COPY --from=native /usr/local/openssh-10.4p1 /usr/local/openssh-10.4p1

# Put the OpenSSH client tools ahead of Debian's for login shells and sudo's
# secure_path too, and name each OpenSSL explicitly: openssl-4.0.1 is the
# isolated build (also first on PATH), openssl-3 the system one that can load
# the libp11 ENGINE.
RUN for ossh_bin in scp sftp ssh ssh-add ssh-agent ssh-keygen ssh-keyscan; do \
        ln -sf "/usr/local/openssh-10.4p1/bin/${ossh_bin}" "/usr/local/bin/${ossh_bin}"; \
    done && \
    ln -sf /usr/local/openssl-4.0.1/bin/openssl /usr/local/bin/openssl-4.0.1 && \
    ln -sf /usr/bin/openssl /usr/local/bin/openssl-3

# libtpms where swtpm expects it, then refresh the library cache.
RUN libdir="/lib/$(gcc -dumpmachine)" && mkdir -p "${libdir}" && \
    ln -sf /usr/lib/libtpms.so.0.10.1 "${libdir}/libtpms.so.0.10.1" && \
    ln -sf "${libdir}/libtpms.so.0.10.1" "${libdir}/libtpms.so.0" && \
    ln -sf "${libdir}/libtpms.so.0.10.1" "${libdir}/libtpms.so" && \
    ldconfig

# The non-root user every CI stage runs as (uid 10001, as the compose services
# and scripts/in-toolchain-image.sh expect), owning the token and TPM state.
RUN groupadd --gid 10001 dev && \
    useradd --uid 10001 --gid 10001 --no-create-home --home-dir /home/dev --shell /bin/bash dev && \
    install -d -o dev -g dev /home/dev /src /var/lib/softhsm/tokens /var/lib/swtpm/state && \
    printf '%s\n' \
        'directories.tokendir = /var/lib/softhsm/tokens' \
        'objectstore.backend = file' \
        'log.level = INFO' > /etc/softhsm/softhsm2.conf

# /usr/local/openssl-4.0.1/bin and /usr/local/openssh-10.4p1/bin lead PATH so
# `openssl` and `ssh` resolve to the source builds. This changes command
# resolution only: no shared-library search path, so apt/curl/git/cgo keep
# the system libssl3. Login shells reset PATH from /etc/profile, so
# /etc/profile.d pins the same order again.
ENV PATH=/usr/local/openssh-10.4p1/bin:/usr/local/openssl-4.0.1/bin:/usr/local/go/bin:$PATH \
    SSL_CERT_DIR=/etc/ssl/certs \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf \
    PKCS11_LIBRARY=/usr/lib/softhsm/libsofthsm2.so \
    SWTPM_STATE_DIR=/var/lib/swtpm \
    TPM2TOOLS_TCTI=swtpm:path=/var/lib/swtpm/swtpm-sock
RUN printf '%s\n' \
    'PATH=/usr/local/openssh-10.4p1/bin:/usr/local/openssl-4.0.1/bin:/go/bin:/usr/local/go/bin:$PATH' \
    'export PATH' \
    > /etc/profile.d/10-xkms-toolchain.sh

# The verified module cache, readable by every user, and a warm race-enabled
# standard library. After this the image builds and tests offline.
ENV GOTOOLCHAIN=local CGO_ENABLED=1 GOFLAGS=-mod=readonly GOMODCACHE=/gomodcache GOCACHE=/gocache
COPY --from=modules /gomodcache /gomodcache
RUN chmod -R a+rX /gomodcache && \
    go build -race std && \
    chmod -R a+rwX /gocache
ENV GOPROXY=off

# ---------------------------------------------------------------------------
# toolchain: what every CI stage runs in (handbook ci-standard.md §2).
# ---------------------------------------------------------------------------
FROM base AS toolchain
# XKMS_NATIVE_BUILD tells the Makefile every native dependency is in this
# image and no Docker daemon is, so the CGO and xkey builds run in place
# instead of in their builder images.
ENV HOME=/tmp XKMS_NATIVE_BUILD=1
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        coreutils \
        diffutils \
        file \
        findutils \
    && rm -rf /var/lib/apt/lists/* && \
    git config --system --add safe.directory '*'
COPY --from=tools /out/ /usr/local/bin/
COPY --from=tools /opt/node /opt/node
ENV PATH=/opt/node/bin:$PATH
WORKDIR /src
USER dev:dev

# ---------------------------------------------------------------------------
# integration: the source on the base image, for the hardened integration
# service. The compile gate runs at build time, so a stale suite fails here.
# ---------------------------------------------------------------------------
FROM base AS integration
COPY . /src
WORKDIR /src
RUN scripts/vet-integration.sh
ENV HOME=/home/dev
USER dev

# ---------------------------------------------------------------------------
# devcontainer: the interactive harness (compose.yaml, devcontainer.json).
# ---------------------------------------------------------------------------
FROM toolchain AS devcontainer
LABEL maintainer="go-xkms"
LABEL description="Development environment for go-xkms with ALL build and test dependencies"
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    git-lfs \
    # Networking and testing tools
    wget \
    netcat-openbsd \
    iputils-ping \
    dnsutils \
    # Chromium, and with it the browser runtime libraries Playwright needs,
    # for the WebAuthn RP ceremony suite (test/integration/webauthn-browser)
    chromium \
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
    && rm -rf /var/lib/apt/lists/*
COPY --from=tools /devout/ /usr/local/bin/

# Non-root user for VS Code
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID
RUN groupadd --gid $USER_GID $USERNAME && \
    useradd --uid $USER_UID --gid $USER_GID -m $USERNAME && \
    echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME && \
    chmod 0440 /etc/sudoers.d/$USERNAME && \
    usermod -aG docker $USERNAME && \
    mkdir -p /workspace /etc/xkms /data /var/run/xkms /go/pkg/mod /home/$USERNAME/.cache/go-build && \
    chown -R $USERNAME:$USERNAME /workspace /var/lib/softhsm /var/lib/swtpm /etc/softhsm \
        /etc/xkms /data /var/run/xkms /go /home/$USERNAME

# XKMS_DEVCONTAINER is the positive devcontainer identity marker. The
# Makefile's run_in_devcontainer / run_with_server helpers test it instead of
# /.dockerenv, which is true in ANY container -- including a CI job container
# -- and made the act_runner job impersonate the devcontainer so the harness
# never started one (go-xkms #19).
#
# The harness resolves modules over the network into its own cache volume, so
# the offline toolchain settings are reset here.
ENV XKMS_DEVCONTAINER=1 \
    HOME=/home/$USERNAME \
    GOPATH=/go \
    GOMODCACHE=/go/pkg/mod \
    GOCACHE=/home/$USERNAME/.cache/go-build \
    GOPROXY=https://proxy.golang.org,direct \
    GOFLAGS=-buildvcs=false \
    FIDO2_PIN=123456 \
    PATH=/go/bin:$PATH

USER $USERNAME

# SoftHSM token for testing. Token: xkms-test, SO PIN: 1234, User PIN: 1234, Slot: 0
RUN softhsm2-util --init-token --slot 0 --label "xkms-test" --so-pin 1234 --pin 1234

WORKDIR /workspace
CMD ["sleep", "infinity"]
