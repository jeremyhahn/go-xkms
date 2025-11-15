FROM golang:1.25

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto

WORKDIR /app

CMD ["sh", "-c", "echo 'Running Azure Key Vault integration tests with mock client...'; go test -v -tags='integration azurekv' ./test/integration/azurekv/..."]
