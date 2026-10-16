VERSION ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: check fmt vet lint test test-dynamo dev build sam-build deploy

## check: everything CI runs (the merge gate)
check: fmt vet lint test

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "gofmt: files need formatting" && exit 1)

vet:
	go vet ./...

lint:
	golangci-lint run ./...

test:
	go test -race ./...

## test-dynamo: store tests against DynamoDB Local (docker compose up -d first)
test-dynamo:
	AUTH_TEST_DYNAMO_ENDPOINT=http://localhost:8402 go test -race -run TestDynamoLocal ./internal/store/

## dev: run the API on localhost:4400 against DynamoDB Local with a throwaway key
dev:
	@test -f .env || cp .env.example .env
	@docker compose up -d --wait
	@set -a && . ./.env && set +a && go run -ldflags "$(LDFLAGS)" ./cmd/api

## build: cross-compile both Lambdas (what SAM runs)
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/api/bootstrap ./cmd/api
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/worker/bootstrap ./cmd/worker

# SAM Makefile build method: one target per function, writes bootstrap into $(ARTIFACTS_DIR).
build-ApiFunction:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(ARTIFACTS_DIR)/bootstrap ./cmd/api

build-WorkerFunction:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(ARTIFACTS_DIR)/bootstrap ./cmd/worker

sam-build:
	sam build --template infra/template.yaml

## deploy: what CI runs on main. Needs AWS credentials (CI uses the OIDC role).
deploy: sam-build
	sam deploy --no-confirm-changeset --no-fail-on-empty-changeset
