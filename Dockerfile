FROM golang:1.25.7-alpine3.23 AS firewall

ARG TARGETARCH

WORKDIR /app

# Install dependencies
COPY go.mod .
COPY go.sum .
RUN go mod download

# Build app
COPY src src
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o build/firewall src/main.go

FROM scratch

# Configure firewall
COPY --from=firewall /app/build/firewall /firewall

ENTRYPOINT ["/firewall"]
