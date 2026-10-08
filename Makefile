.PHONY: test build edge client deploy
test:
	cd edge && bun test
	cd client && go vet ./... && go test ./...
	cd deploy && go vet ./... && go test ./...
edge:
	cd edge && bun run build
client:
	cd client && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../dist/edgeguard ./cmd/edgeguard
deploy: edge
	cp edge/dist/edge-script.js deploy/edgescript/bundle/
	cd deploy && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../dist/edgeguard-deploy ./cmd/edgeguard-deploy
build: edge client deploy
