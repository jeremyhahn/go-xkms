# Multi-stage build for SoftHSM v2
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
    openssl-dev \
    sqlite-dev \
    p11-kit-dev

# Build SoftHSM v2.6.1
WORKDIR /build
RUN git clone https://github.com/opendnssec/SoftHSMv2.git && \
    cd SoftHSMv2 && \
    git checkout 2.6.1 && \
    sh autogen.sh && \
    ./configure \
        --prefix=/usr/local \
        --disable-gost \
        --with-crypto-backend=openssl \
        --with-objectstore-backend-db \
        --with-sqlite3=/usr && \
    make -j$(nproc) && \
    make install DESTDIR=/build/softhsm-install

# Runtime stage
FROM alpine:3.22.1

# Install runtime dependencies only
RUN apk add --no-cache \
    openssl \
    sqlite-libs \
    p11-kit \
    p11-kit-server

# Copy built artifacts from builder
COPY --from=builder /build/softhsm-install/usr/local /usr/local

# Create non-root user for running SoftHSM
RUN addgroup -g 1000 softhsm && \
    adduser -D -u 1000 -G softhsm softhsm

# Create token directory with proper permissions
RUN mkdir -p /tokens && \
    chown -R softhsm:softhsm /tokens

# Copy configuration file
COPY softhsm2.conf /home/softhsm/softhsm2.conf
RUN chown softhsm:softhsm /home/softhsm/softhsm2.conf

# Set environment variables
ENV SOFTHSM2_CONF=/home/softhsm/softhsm2.conf
ENV PKCS11_LIBRARY=/usr/local/lib/softhsm/libsofthsm2.so

# Update library cache
RUN ldconfig /usr/local/lib || true

# Switch to non-root user
USER softhsm

# Set working directory
WORKDIR /home/softhsm

# Health check to verify SoftHSM library is accessible
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD test -f /usr/local/lib/softhsm/libsofthsm2.so || exit 1

# Keep container running for service access
CMD ["tail", "-f", "/dev/null"]
