VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD   ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  = -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD)

.PHONY: build test clean docker

build:
	go build -buildvcs=false -ldflags "$(LDFLAGS)" -o vpnctl ./cmd/vpnctl

test:
	go test ./...

clean:
	rm -f vpnctl

docker:
	docker build -t vpnctl:$(VERSION) .
