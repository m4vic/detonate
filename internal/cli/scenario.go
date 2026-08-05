package cli

import (
	"fmt"

	"github.com/m4vic/detonate/internal/scenario"
)

const scenarioUsage = `Usage:
  detonate scenario validate <file>

Validate a versioned JSON or YAML scenario document without starting Docker or
executing a target. This is the safe first check for shared MCP, skill, and
prompt test cases.
`

// runScenario contains the scenario-file commands that do not execute target
// code. Scenario execution will be added only after its sandbox runner exists.
func (a *App) runScenario(args []string) int {
	if len(args) != 2 || args[0] != "validate" {
		fmt.Fprint(a.Stderr, scenarioUsage)
		return exitUsage
	}
	document, err := scenario.LoadFile(args[1])
	if err != nil {
		fmt.Fprintf(a.Stderr, "detonate: invalid scenario file: %v\n", err)
		return exitUsage
	}
	fmt.Fprintf(a.Stdout, "valid scenario document: %d scenario(s), schema %s\n",
		len(document.Scenarios), document.Schema)
	return exitOK
}
