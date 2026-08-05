// Command detonate runs untrusted AI-connected tools in a sandbox and reports
// what they actually do.
//
// This file stays deliberately tiny. Everything worth testing lives in
// internal/cli, which returns an exit code instead of calling os.Exit, so the
// only thing not under test is the four lines below.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/m4vic/detonate/internal/cli"
)

func main() {
	// NotifyContext so Ctrl-C cancels the context rather than killing us
	// outright. That cancellation propagates into the MCP driver and, from
	// M2, into container teardown: an interrupted scan must not leave an
	// untrusted process or container running.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	os.Exit(cli.New().Run(ctx, os.Args[1:]))
}
