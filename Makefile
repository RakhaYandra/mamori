.PHONY: build run vet test race cover lint fmt check audit clean install man

PREFIX ?= $(HOME)/.local
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v0.1.0-dev)
LDFLAGS := -X main.version=$(VERSION)

build:
	go build -ldflags "$(LDFLAGS)" -o bin/mamori ./cmd/mamori

release:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/mamori-linux-amd64 ./cmd/mamori
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/mamori-linux-arm64 ./cmd/mamori
	sha256sum dist/mamori-linux-amd64 dist/mamori-linux-arm64 > dist/SHA256SUMS
	cat dist/SHA256SUMS

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

man: build
	./bin/mamori man --dir docs/man

check: vet test audit
	golangci-lint run

# Ban shell execution: exec'ing sh/bash, -c flags, absolute shell paths,
# os.system, eval. Plain mentions (e.g. completion shell names) are fine.
audit:
	@echo "== shell-execution audit =="
	@hits=$$(grep -rn --include='*.go' -E 'exec\.Command\([^)]*"(sh|bash)"|sh +-c|bash +-c|/bin/sh|/bin/bash|os\.system|eval\(' . || true); \
	if [ -n "$$hits" ]; then echo "$$hits"; echo "FAIL: shell execution patterns found"; exit 1; fi
	@echo "clean: no shell execution patterns"

clean:
	rm -rf bin/ dist/

install: build
	install -Dm755 bin/mamori $(PREFIX)/bin/mamori
