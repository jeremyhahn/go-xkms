# SoftHSM 2.7.0 from its pinned, checksum-verified release
# (scripts/build-softhsm.sh) instead of Debian's 2.6.1, which answers an AES-GCM
# tag mismatch with the ambiguous CKR_GENERAL_ERROR so PKCS#11 tamper could not
# be classified as types.ErrSealedDataAuthentication (go-xkms#1418).
FROM golang:1.27.4-bookworm AS softhsm
RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf automake libtool libssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/build-softhsm.sh /build/build-softhsm.sh
RUN DESTDIR=/build/softhsm-install sh /build/build-softhsm.sh

FROM golang:1.27.4-bookworm

RUN apt-get update && apt-get install -y \
    ca-certificates \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# SoftHSM 2.7.0: /usr/lib/softhsm/libsofthsm2.so, softhsm2-util, /etc/softhsm.
COPY --from=softhsm /build/softhsm-install/ /

ENV GOTOOLCHAIN=auto
ENV GOWORK=off
ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf

WORKDIR /app

# Bake the source into the image at build time -- see pkcs8/Dockerfile's
# identical comment for why the compose file's runtime bind mount
# (`volumes: - ../../..:/app`) is unreliable on the Gitea Actions runner.
COPY go.mod go.sum ./
COPY sdk/go/go.mod sdk/go/go.sum ./sdk/go/
COPY xkey/go.mod xkey/go.sum ./xkey/

RUN --mount=type=secret,id=gomodauth \
    set -eu; \
    if [ -f /run/secrets/gomodauth ]; then . /run/secrets/gomodauth; fi; \
    go mod download

COPY . .

CMD ["sh", "-c", "echo 'Initializing SoftHSM2...'; softhsm2-util --init-token --slot 0 --label 'test-token' --so-pin 1234 --pin 1234; echo 'SoftHSM2 is ready, running tests...'; go test -v -tags='integration pkcs11 codec_cbor codec_json codec_msgpack gms_pure_go' ./test/integration/pkcs11"]
