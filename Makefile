.PHONY: test build edge worker client sbom
test:
	cd edge && bun test
	cd client && go vet ./... && go test ./...
edge:
	cd edge && bun run build
worker:
	cd edge && bun run build:worker
# vabbit embeds the edge script, so `vabbit deploy` needs no Bun or Node.
client: edge
	cp edge/dist/edge-script.js client/internal/deploy/edgescript/bundle/
	cd client && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../dist/vabbit ./cmd/vabbit
build: client
sbom:
	./scripts/sbom.sh
