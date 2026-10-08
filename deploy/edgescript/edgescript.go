// Package edgescript carries the built edge script inside edgeguard-deploy,
// so deploying needs no Bun or Node. `make deploy` copies edge/dist into
// bundle/ before building; without it, pass --script or set script in the config.
package edgescript

import "embed"

//go:embed bundle
var files embed.FS

// Code returns the embedded edge script, or "" if none was built in.
func Code() string {
	b, err := files.ReadFile("bundle/edge-script.js")
	if err != nil {
		return ""
	}
	return string(b)
}
