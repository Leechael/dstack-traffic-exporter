.PHONY: all build clean linux

# Get the git commit hash and build time
GIT_COMMIT := $(shell git rev-parse HEAD)
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
VERSION := 0.1.0

# Build flags
BUILD_FLAGS := -ldflags "-X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildTime=$(BUILD_TIME)"

# Default target
all: linux

# Build for Linux AMD64
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o haproxy-sni-traffic-exporter-linux-amd64 main.go

# Clean build artifacts
clean:
	rm -f haproxy-sni-traffic-exporter-linux-amd64