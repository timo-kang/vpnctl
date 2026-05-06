FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN make build

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard-tools iproute2 ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /src/vpnctl /usr/local/bin/vpnctl
ENTRYPOINT ["vpnctl"]
