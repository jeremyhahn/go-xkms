FROM golang:1.25.5

RUN apt-get update && apt-get install -y ca-certificates curl netcat-openbsd && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=auto

WORKDIR /app

CMD ["sh", "-c", "echo 'Waiting for Vault to be ready...'; \
     while ! curl -sf http://vault:8200/v1/sys/health > /dev/null; do sleep 1; done; \
     echo 'Vault is ready!'; \
     echo 'Enabling Transit engine...'; \
     curl -X POST -H 'X-Vault-Token: root' -d '{\"type\":\"transit\"}' http://vault:8200/v1/sys/mounts/transit; \
     echo ''; \
     echo 'Transit engine setup complete!'; \
     echo 'Running tests...'; \
     go test -v -tags='integration vault' ./test/integration/vault/..."]
