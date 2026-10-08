module vabbit-deploy

go 1.23.1

require github.com/BurntSushi/toml v1.4.0

require vabbit v0.0.0

require (
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/term v0.31.0 // indirect
)

// The admin login format is shared with the vabbit client.
replace vabbit => ../client
