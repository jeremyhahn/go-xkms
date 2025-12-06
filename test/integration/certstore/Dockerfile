FROM golang:1.25.5-alpine

RUN apk add --no-cache git make gcc musl-dev

WORKDIR /workspace

COPY go.mod go.sum ./
RUN go mod download

COPY . .

CMD ["go", "test", "-v", "-tags=integration", "./test/integration/certstore/..."]
