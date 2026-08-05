package scan

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/m4vic/detonate/internal/acquire"
	"github.com/m4vic/detonate/internal/assessment"
	"github.com/m4vic/detonate/internal/mcpdriver"
	"github.com/m4vic/detonate/internal/monitor"
	"github.com/m4vic/detonate/internal/probe"
	"github.com/m4vic/detonate/internal/sandbox"
	"github.com/m4vic/detonate/internal/scenario"
)

// runMCP acquires, launches, enumerates and probes an MCP server.
func runMCP(ctx context.Context, req Request, p Progress) (*Report, error) {
	tgt := req.Target
	policy := sandbox.DefaultPolicy()

	var mounts []sandbox.Mount
	var absDir string
	if req.MountDir != "" {
		abs, err := filepath.Abs(req.MountDir)
		if err != nil {
			return nil, fmt.Errorf("resolving target directory: %w", err)
		}
		absDir = abs
		// Read-only, always. A target that can rewrite its own source
		// mid-scan makes the evidence disagree with the artifact, which
		// defeats the point of collecting evidence at all.
		mounts = append(mounts, sandbox.Mount{
			HostPath: abs, ContainerPath: "/target", ReadOnly: true,
		})
	}

	var scenarios []assessment.ScenarioResult

	// Phase 1 runs the package manager with a network. Target-controlled
	// lifecycle and build hooks may execute here; the separate container
	// limits persistence but does not make acquisition inert.
	var installed *acquire.Result
	if req.Stages.Install {
		if absDir == "" {
			return nil, errors.New("installing dependencies needs a target directory to read a manifest from")
		}
		m := acquire.Detect(absDir)
		if m.Ecosystem == acquire.EcosystemNone {
			p.step("  no dependency manifest found; skipping install")
		} else {
			p.step(fmt.Sprintf("  [1/2] installing %s deps from %s "+
				"(separate container, network ON, hooks may execute)", m.Ecosystem, m.File))
		}

		res, err := acquire.Install(ctx, absDir, policy)
		if err != nil {
			return nil, targetError("acquire", "acquisition_failed", true, err)
		}
		installed = res
		defer func() { _ = installed.Cleanup(context.Background()) }()

		mounts = append(mounts, installed.Mounts()...)
		policy.Env = installed.Env

		// Detonate on the runtime the dependencies were built for. A Node
		// package installed into a volume is useless inside a Python image:
		// the deps are present but `node` is not.
		if installed.Image != "" {
			policy.Image = installed.Image
		}

		// A project that had to be compiled now lives in the volume, not at
		// /target. Detection ran before the build and could only name the
		// entry point the package declares, which did not exist on disk yet.
		if rewritten := installed.Command(tgt.Reference); rewritten != tgt.Reference {
			p.step(fmt.Sprintf("  built   running from %s", installed.Root))
			tgt.Reference = rewritten
		}
	}

	// Always sandboxed. There is no host-execution path reachable from here:
	// the unsandboxed EnumerateTools still exists for our own tests, but
	// shipping a way to reach it would recreate exactly the
	// --dangerously-run-mcp-servers hole that justifies this tool.
	phase := ""
	if req.Stages.Install {
		phase = "[2/2] "
	}
	p.step(fmt.Sprintf("  %slaunching target inside a sandbox "+
		"(network off, read-only root, no capabilities, non-root)", phase))

	if !req.Stages.Probe {
		res, err := mcpdriver.EnumerateSandboxedWithTrace(ctx, tgt.Reference, policy, mounts)
		if err != nil {
			return nil, targetError("inventory", "mcp_inventory_failed", false, err)
		}
		// Fold install-time behaviour into the same trace. A postinstall hook
		// that phoned home is a finding about this target, and splitting it
		// into a separate report would let it be overlooked.
		if installed != nil && res.Trace != nil {
			res.Trace.Events = append(installed.Events, res.Trace.Events...)
		}
		scenarios = append(scenarios, assessment.ScenarioResult{
			ID: "mcp.inventory", Required: true, Outcome: assessment.OutcomePass,
		})
		for _, tool := range res.Tools {
			scenarios = append(scenarios, assessment.ScenarioResult{
				ID:       scenario.MCPToolID(tool.Name),
				Required: true,
				Outcome:  assessment.OutcomeSkipped,
				Reason:   "dynamic probes were disabled",
			})
		}
		return &Report{
			Tools: res.Tools, Trace: res.Trace,
			Scenarios: scenarios, Reference: tgt.Reference,
		}, nil
	}

	// Probing keeps the session open: a tool only reveals what it does when it
	// is called, so the container has to outlive tools/list.
	sess, err := mcpdriver.OpenSession(ctx, tgt.Reference, policy, mounts)
	if err != nil {
		return nil, targetError("start", "mcp_start_failed", false, err)
	}
	defer sess.Close()

	tools, err := sess.Tools(ctx)
	if err != nil {
		return nil, targetError("inventory", "mcp_inventory_failed", false, err)
	}
	scenarios = append(scenarios, assessment.ScenarioResult{
		ID: "mcp.inventory", Required: true, Outcome: assessment.OutcomePass,
	})

	tr := newTrace(tgt.Reference)
	if installed != nil {
		for _, ev := range installed.Events {
			tr.Add(ev)
		}
	}

	// Enumeration-phase behaviour: what the server did just from being
	// launched and asked for its tool list, BEFORE any tool was called. A
	// network attempt here is unprovoked — nobody invoked anything — so it is
	// the real phone-home signal and stays a finding.
	//
	// Captured before probing on purpose. A tool that legitimately reaches its
	// own API when we call it must not be confused with the server reaching
	// out on its own; only the second is suspicious.
	for _, ev := range monitor.Analyze(sess.Stderr(), "enumeration") {
		tr.Add(ev)
	}

	p.step(fmt.Sprintf("  probing %d tool(s) with %d adversarial payload(s)...",
		len(tools), len(probe.Payloads())))

	// The engine attributes probe-phase behaviour to the specific payload and
	// tool that provoked it, and skips tools that need the network (their
	// egress is expected, not a finding). There is deliberately no aggregate
	// re-scan of the whole stderr buffer afterwards: it re-flagged the
	// expected, blocked network noise from every API-backed tool as a critical
	// finding, which turned a clean Notion server into "dangerous".
	probeResult := probe.RunWithResults(ctx, sess, tools, 0)
	for _, ev := range probeResult.Events {
		tr.Add(ev)
	}
	scenarios = append(scenarios, probeResult.Scenarios...)

	return &Report{
		Tools: tools, Trace: tr,
		Scenarios: scenarios, Reference: tgt.Reference,
	}, nil
}
