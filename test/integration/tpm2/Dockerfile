FROM golang:1.25.5

# Install dependencies including tcpdump for optional packet capture debugging
RUN apt-get update && apt-get install -y \
    ca-certificates \
    netcat-openbsd \
    build-essential \
    libssl-dev \
    tcpdump \
    tpm2-tools \
    && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto
ENV CGO_ENABLED=1

WORKDIR /app

# Run all TPM2 integration tests including encryption verification
CMD ["sh", "-c", "echo 'Waiting for TPM simulator to be ready...'; while ! nc -z tpm-simulator 2421; do sleep 1; done; echo 'TPM simulator is ready, running tests...'; go test -v -tags='integration tpm2' -timeout 30m ./test/integration/tpm2/..."]
