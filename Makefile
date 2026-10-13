.PHONY: build run vet test race cover lint fmt check audit clean install

PREFIX ?= $(HOME)/.local
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.1.0-dev)
LDFLAGS := -X main.version=$(VERSION)

build:
	go build -ldflags "$(LDFLAGS)" -o bin/mamori ./cmd/mamori

release:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/mamori-linux-amd64 ./cmd/mamori

run: build
	./bin/mamori

test:
	go test ./...

race:
	go test -race ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -n 5

vet:
	go vet ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .

check: vet test audit
	golangci-lint run

# Ban shell-execution patterns. Structured exec (os/exec arg list) only.
audit:
	@echo "== shell-execution audit =="
	@hits=$$(grep -rn --include='*.go' -E '"sh"|"bash"|sh +-c|bash +-c|/bin/sh|/bin/bash|os\.system|eval\(' . || true); \
	if [ -n "$$hits" ]; then echo "$$hits"; echo "FAIL: shell execution patterns found"; exit 1; fi
	@echo "clean: no shell execution patterns"

clean:
	rm -rf bin/ dist/

install: build
	install -Dm755 bin/mamori $(PREFIX)/bin/mamori
