# Multi-stage build for SWTPM TPM 2.0 simulator
# Based on Alpine 3.22.1 for minimal image size

# Build stage
FROM alpine:3.22.1 AS builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    build-base \
    automake \
    autoconf \
    libtool \
    bash \
    gawk \
    socat \
    libseccomp-dev \
    gnutls-dev \
    libtasn1-dev \
    expect \
    json-glib-dev \
    glib-dev \
    openssl-dev

# Build libtpms from specific commit
WORKDIR /build
RUN git clone https://github.com/stefanberger/libtpms.git && \
    cd libtpms && \
    git checkout b4d81572c15b504a4e60b4b46c91d3ec0a92c79e && \
    ./autogen.sh --prefix=/usr --with-openssl --with-tpm2 && \
    make -j$(nproc) && \
    make install DESTDIR=/build/libtpms-install

# Build SWTPM from specific commit
WORKDIR /build
RUN git clone https://github.com/stefanberger/swtpm.git && \
    cd swtpm && \
    git checkout 665486b8179fef6eba845e8437acd2da6ae2634e && \
    # Copy libtpms libraries for build
    cp -r /build/libtpms-install/usr/* /usr/ && \
    ./autogen.sh --prefix=/usr --with-openssl --with-tpm2 && \
    make -j$(nproc) && \
    make install DESTDIR=/build/swtpm-install

# Runtime stage
FROM alpine:3.22.1

# Install runtime dependencies only
RUN apk add --no-cache \
    gnutls \
    libtasn1 \
    json-glib \
    glib \
    openssl \
    libseccomp \
    socat \
    netcat-openbsd \
    su-exec

# Copy built artifacts from builder
COPY --from=builder /build/libtpms-install/usr /usr
COPY --from=builder /build/swtpm-install/usr /usr

# Create non-root user for running SWTPM
RUN addgroup -g 1000 tpm && \
    adduser -D -u 1000 -G tpm tpm

# Create TPM state directory with proper permissions
RUN mkdir -p /var/lib/swtpm/tpmstate && \
    chown -R tpm:tpm /var/lib/swtpm

# Expose TPM command and control ports
EXPOSE 2321 2322

# Switch to non-root user
USER tpm

# Set working directory
WORKDIR /var/lib/swtpm

# Health check to verify SWTPM is responding
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD nc -z localhost 2321 || exit 1

# Start SWTPM server with TCP socket
CMD ["/usr/bin/swtpm", "socket", \
     "--tpmstate", "dir=/var/lib/swtpm/tpmstate", \
     "--tpm2", \
     "--server", "type=tcp,port=2321,bindaddr=0.0.0.0", \
     "--ctrl", "type=tcp,port=2322,bindaddr=0.0.0.0", \
     "--flags", "startup-clear,not-need-init", \
     "--log", "level=20"]
