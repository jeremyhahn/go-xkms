FROM golang:1.25

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto

WORKDIR /app

CMD ["sh", "-c", "echo 'Waiting for LocalStack to be ready...'; while ! curl -sf http://localstack:4566/_localstack/health > /dev/null; do sleep 1; done; echo 'LocalStack is ready, running tests...'; go test -v -tags='integration awskms' ./test/integration/awskms/..."]
