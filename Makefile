.PHONY: test build edge client
test:
	cd edge && bun test
	cd client && go vet ./... && go test ./...
edge:
	cd edge && bun run build
client:
	cd client && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../dist/edgeguard ./cmd/edgeguard
build: edge client
