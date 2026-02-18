BINARY_NAME=joern_audit
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS=-ldflags "-X github.com/joern-audit/joern_audit/internal/config.Version=$(VERSION) -X github.com/joern-audit/joern_audit/internal/config.BuildTime=$(BUILD_TIME)"

.PHONY: build clean test lint run help

build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/joern_audit

run: build
	./bin/$(BINARY_NAME)

test:
	go test -v ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/ *.db

deps:
	go mod tidy
	go mod download

install: build
	cp bin/$(BINARY_NAME) $(GOPATH)/bin/

help:
	@echo "Available targets:"
	@echo "  build    - Build the binary"
	@echo "  run      - Build and run"
	@echo "  test     - Run tests"
	@echo "  lint     - Run linter"
	@echo "  clean    - Remove build artifacts"
	@echo "  deps     - Download dependencies"
	@echo "  install  - Install to GOPATH/bin"
