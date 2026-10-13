// Command mamori is a local-first Linux security auditor for developer machines.
package main

import (
	"os"

	"github.com/RakhaYandra/mamori/internal/cli"
)

var version = "v0.1.0-dev"

func main() {
	if err := cli.NewRootCmd(version).Execute(); err != nil {
		os.Exit(2)
	}
}
