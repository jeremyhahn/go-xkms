# Multi-stage build for SoftHSM v2
# Based on Alpine for minimal image size
# Pinned to the 3.24 minor series, bumped from 3.22.1 (two minors stale). The
# series tag keeps the build reproducible while still receiving patches, and
# the apk upgrade in each stage takes them on rebuild; a patch-level pin would
# freeze the fixes. SoftHSM below is built from source at a pinned upstream tag
# against the base toolchain, so a base bump moves that toolchain -- verify a
# clean build of this image when bumping the series again.

# Build stage
FROM alpine:3.24 AS builder

# Install build dependencies
RUN apk --no-cache upgrade && apk add --no-cache \
    build-base \
    automake \
    autoconf \
    libtool \
    pkgconf \
    openssl-dev \
    curl

# Build SoftHSM 2.7.0 from its pinned, checksum-verified release. 2.6.1, built
# here before, answers an AES-GCM tag mismatch with the ambiguous
# CKR_GENERAL_ERROR, so PKCS#11 tamper could not be classified as
# types.ErrSealedDataAuthentication (go-xkms#1418). The pin lives in the
# repository's scripts/build-softhsm.sh, which every compose file that builds
# this image passes in as the named build context "softhsm-pin". Only the file
# object store is used (softhsm2.conf), so the SQLite backend is not built.
COPY --from=softhsm-pin build-softhsm.sh /build/build-softhsm.sh
RUN DESTDIR=/build/softhsm-install sh /build/build-softhsm.sh /usr/local

# Runtime stage
FROM alpine:3.24

# Install runtime dependencies only. SoftHSM is C++, and the builder stage
# gets libstdc++/libgcc for free from build-base while this stage copies only
# /usr/local -- so the C++ runtime must be installed here explicitly or
# libsofthsm2.so and softhsm2-util cannot load (#227).
RUN apk --no-cache upgrade && apk add --no-cache \
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

# Health check that actually loads the SoftHSM library. A bare `test -f`
# passes even when the .so cannot load (the exact failure mode of #227);
# softhsm2-util links the same C++ runtime and opens the token store, so it
# fails whenever the library would.
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD softhsm2-util --show-slots >/dev/null 2>&1 || exit 1

# Keep container running for service access
CMD ["tail", "-f", "/dev/null"]
