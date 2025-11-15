FROM golang:1.25

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto

WORKDIR /app

CMD ["sh", "-c", "echo 'Running GCP KMS integration tests with mock client...'; go test -v -tags='integration gcpkms' ./test/integration/gcpkms/..."]
