SHELL = /bin/bash
MODULE = $(shell go list -m)
BIN  = $(CURDIR)/bin
V = 0
Q = $(if $(filter 1,$V),,@)
M = $(shell printf "\033[34;1m▶\033[0m")

GO      = go
.PHONY: all
all: deps build

build: deps | $(BIN) ; $(info $(M) building executable…) @ ## Build program binary
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build \
                -mod=vendor \
                -o $(BIN)/$(shell basename $(MODULE)) main.go

.PHONY: run
run:
	$(GO) run main.go

deps:
	go clean --modcache
	go mod tidy
	go mod vendor

