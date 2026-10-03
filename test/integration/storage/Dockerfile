# Shared test-runner image for all storage integration lanes (test,
# test-file, test-memory, test-hardware-pkcs11, test-hardware-tpm2). The six
# services in docker-compose.yml differ only in which extra apt packages
# they need and which `go test -run` filter/tags they invoke -- the latter
# stays a per-service `command:` in compose, the former is EXTRA_APT_PACKAGES
# below, so one image serves all of them.
#
# Previously each service ran bare `image: golang:bookworm` with the repo
# bind-mounted at runtime (`volumes: - ../../..:/app`) and did
# `apt-get install` + implicit `go mod download` inside `command:`. On the
# Gitea Actions runner that relative bind mount resolves against the JOB
# CONTAINER's filesystem, which the HOST docker daemon doesn't share -- the
# mount silently succeeds against an unrelated (often empty) host directory
# instead of erroring, leaving /app without a go.mod (same failure class
# runner-log-proven for test/integration/pkcs8, task 3001, and already fixed
# the same way for the other nine lanes). This bakes the source into the
# image at build time instead.
# SoftHSM 2.7.0 from its pinned, checksum-verified release
# (scripts/build-softhsm.sh) instead of Debian's 2.6.1, which answers an AES-GCM
# tag mismatch with the ambiguous CKR_GENERAL_ERROR so PKCS#11 tamper could not
# be classified as types.ErrSealedDataAuthentication (go-xkms#1418).
FROM golang:1.27.0-bookworm AS softhsm
RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf automake libtool libssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/build-softhsm.sh /build/build-softhsm.sh
RUN DESTDIR=/build/softhsm-install sh /build/build-softhsm.sh

FROM golang:bookworm

ARG EXTRA_APT_PACKAGES=""
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates ${EXTRA_APT_PACKAGES} \
    && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto
ENV GOWORK=off

# Every lane gets the same SoftHSM; only test-hardware-pkcs11 loads it.
# SoftHSM 2.7.0: /usr/lib/softhsm/libsofthsm2.so, softhsm2-util, /etc/softhsm.
COPY --from=softhsm /build/softhsm-install/ /

WORKDIR /app

COPY go.mod go.sum ./
COPY sdk/go/go.mod sdk/go/go.sum ./sdk/go/
COPY xkey/go.mod xkey/go.sum ./xkey/

# In-house modules resolve from Gitea tags (dependency-resolution.md §6). The
# fetch token arrives as a BuildKit secret, never a build arg or ENV, mounted
# on tmpfs for this RUN alone and never becoming a layer. Optional by
# design: with no secret supplied these modules resolve from the public
# proxy once tags are mirrored (§7).
RUN --mount=type=secret,id=gomodauth \
    set -eu; \
    if [ -f /run/secrets/gomodauth ]; then . /run/secrets/gomodauth; fi; \
    go mod download

COPY . .
