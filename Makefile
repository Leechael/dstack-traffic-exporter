.PHONY: all build clean linux darwin local

# Get the git commit hash and build time
GIT_COMMIT := $(shell git rev-parse HEAD)
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
VERSION := 0.1.0

# Build flags
BUILD_FLAGS := -ldflags "-X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildTime=$(BUILD_TIME)"

# Default target
all: linux

# Build for current platform (local development)
local:
	go build $(BUILD_FLAGS) -o dstack-traffic-exporter main.go

# Build for macOS
darwin:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(BUILD_FLAGS) -o dist/traffic-exporter-darwin-amd64 main.go

# Build for Linux AMD64
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o dist/traffic-exporter-linux-amd64 main.go

# Clean build artifacts
clean:
	rm -f dist/* dstack-traffic-exporter