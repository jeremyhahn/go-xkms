FROM golang:1.25.5

RUN apt-get update && apt-get install -y \
    ca-certificates \
    netcat-openbsd \
    softhsm2 \
    libsofthsm2 \
    && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto
ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf

WORKDIR /app

CMD ["sh", "-c", "echo 'Initializing SoftHSM2...'; softhsm2-util --init-token --slot 0 --label 'test-token' --so-pin 1234 --pin 1234; echo 'SoftHSM2 is ready, running tests...'; go test -v -tags='integration pkcs11' ./test/integration/pkcs11/..."]
