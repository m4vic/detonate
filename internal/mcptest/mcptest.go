// Package mcptest provides a real MCP server for detonate's own tests.
//
// It is not a mock in the sense of faking the protocol. It is a genuine server
// built on the official SDK, run as a real subprocess over a real stdio pipe.
// Testing our real client against a real server is what makes a green test
// mean "the protocol works" rather than "the function names match".
//
// The trick is that the compiled test binary doubles as the server: TestMain
// checks for a flag and, if present, becomes the server instead of running
// tests. That keeps `go test ./...` self-contained, with no second program to
// build or locate at runtime, on any OS.
//
// Usage from a test package:
//
//	func TestMain(m *testing.M) {
//	    mcptest.RunServerIfRequested()
//	    os.Exit(m.Run())
//	}
package mcptest

import (
	"context"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// serverFlag marks a re-exec of the test binary as "be the server".
const serverFlag = "-detonate-mock-mcp-server"

// Command returns the command string that relaunches this test binary as an
// MCP server.
//
// The executable path is quoted because it routinely contains spaces, and on
// Windows it contains backslashes. That is precisely the input a POSIX-style
// tokenizer would mangle, so this doubles as a live check on ParseCommand.
func Command() string {
	return `"` + os.Args[0] + `" ` + serverFlag
}

// RunServerIfRequested turns this process into an MCP server and exits, if it
// was launched with the server flag. Otherwise it returns and the caller runs
// its tests normally.
func RunServerIfRequested() {
	for _, arg := range os.Args[1:] {
		if arg == serverFlag {
			runServer()
			os.Exit(0)
		}
	}
}

type readFileArgs struct {
	Path string `json:"path" jsonschema:"the file to read"`
}

type echoArgs struct {
	Text string `json:"text" jsonschema:"the text to echo back"`
}

func runServer() {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "detonate-test-fixture",
		Version: "v0.0.1",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "read_file",
		Description: "Read the contents of a file at the given path.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args readFileArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "(fixture) would read: " + args.Path}},
		}, nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "echo",
		Description: "Echo back the given text.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args echoArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: args.Text}},
		}, nil, nil
	})

	_ = server.Run(context.Background(), &mcp.StdioTransport{})
}
