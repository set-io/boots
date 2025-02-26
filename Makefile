# Makefile for building a Go project

VERSION := $(shell cat VERSION)
GIT_COMMIT := $(shell git rev-parse HEAD)

OS := $(shell uname -s)
ifeq ($(OS),Darwin)
    VERSION_MD5 := $(shell md5 -q VERSION)
else
    VERSION_MD5 := $(shell md5sum VERSION | cut -d' ' -f1)
endif

# Go parameters
GOOS := linux
GOARCH := amd64
BINARY_NAME := boots

# Build the binary
build:
	@GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "-X main.version=${VERSION} -X main.cipher=${VERSION_MD5} -X main.gitCommit=${GIT_COMMIT}" -o $(BINARY_NAME)

# Clean up build artifacts
clean:
	@rm -f $(BINARY_NAME)

# Run the binary
run: build
	./$(BINARY_NAME)

# PHONY targets to prevent conflicts with files named 'build', 'clean', or 'run'
.PHONY: build clean run
