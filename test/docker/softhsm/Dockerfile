# SoftHSM v2 on Alpine 3.24.

# Build stage
FROM alpine:3.24 AS builder
# Optional apk cache as the BuildKit secret apk_mirror; empty when unset.

# Install build dependencies
RUN --mount=type=bind,from=softhsm-pin,source=apk-mirror.sh,target=/usr/local/bin/apk-mirror \
    --mount=type=secret,id=apk_mirror,env=APK_MIRROR \
    apk-mirror --no-cache upgrade && apk-mirror add --no-cache \
    build-base \
    automake \
    autoconf \
    libtool \
    pkgconf \
    openssl-dev \
    curl

# Build SoftHSM 2.7.0 from its pinned, checksum-verified release.
COPY --from=softhsm-pin build-softhsm.sh /build/build-softhsm.sh
RUN DESTDIR=/build/softhsm-install sh /build/build-softhsm.sh /usr/local

# Runtime stage
FROM alpine:3.24
# Optional apk cache as the BuildKit secret apk_mirror; empty when unset.

# Install runtime dependencies only.
RUN --mount=type=bind,from=softhsm-pin,source=apk-mirror.sh,target=/usr/local/bin/apk-mirror \
    --mount=type=secret,id=apk_mirror,env=APK_MIRROR \
    apk-mirror --no-cache upgrade && apk-mirror add --no-cache \
    openssl \
    p11-kit \
    p11-kit-server \
    libstdc++ \
    libgcc

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

# Health check that loads the SoftHSM library.
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD softhsm2-util --show-slots >/dev/null 2>&1 || exit 1

# Keep container running for service access
CMD ["tail", "-f", "/dev/null"]
