package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/m4vic/detonate/internal/acquire"
	"github.com/m4vic/detonate/internal/assessment"
	"github.com/m4vic/detonate/internal/decoy"
	"github.com/m4vic/detonate/internal/mcpdriver"
	"github.com/m4vic/detonate/internal/monitor"
	"github.com/m4vic/detonate/internal/probe"
	"github.com/m4vic/detonate/internal/sandbox"
	"github.com/m4vic/detonate/internal/scenario"
	"github.com/m4vic/detonate/internal/toolscan"
	"github.com/m4vic/detonate/internal/trace"
)

// runMCP acquires, launches, enumerates and probes an MCP server.
func runMCP(ctx context.Context, req Request, p Progress) (out *Report, retErr error) {
	tgt := req.Target
	policy := sandbox.DefaultPolicy()

	var installed *acquire.Result
	var sess *mcpdriver.Session
	defer func() {
		var cleanupErrs []error
		if sess != nil {
			if err := sess.Close(); err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("sandbox: %w", err))
			}
		}
		if installed != nil {
			if err := installed.Cleanup(context.Background()); err != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("dependency volume: %w", err))
			}
		}
		if cleanupErr := errors.Join(cleanupErrs...); cleanupErr != nil {
			if out != nil {
				addTeardownFailure(out, cleanupErr)
				return
			}
			if retErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("teardown failed: %w", cleanupErr))
				return
			}
			retErr = harnessError("teardown", "teardown_failed", false, cleanupErr)
		}
	}()

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

	// Acquisition fetches inert artifacts with network access, then performs
	// every target-controlled install/build step offline and as non-root.
	if req.Stages.Install {
		if absDir == "" {
			return nil, errors.New("installing dependencies needs a target directory to read a manifest from")
		}
		m := acquire.Detect(absDir)
		if m.Ecosystem == acquire.EcosystemNone {
			p.step("  no dependency manifest found; skipping install")
		} else {
			p.step(fmt.Sprintf("  [1/2] fetching %s deps from %s "+
				"(separate container, network ON, scripts disabled)", m.Ecosystem, m.File))
		}

		res, err := acquire.Install(ctx, absDir, policy)
		if err != nil {
			var unsupported *acquire.UnsupportedError
			if errors.As(err, &unsupported) {
				var acquisitionTrace *trace.Trace
				if len(unsupported.Events) > 0 {
					acquisitionTrace = newTrace(tgt.Reference)
					acquisitionTrace.Events = append(acquisitionTrace.Events,
						unsupported.Events...)
				}
				return &Report{
					Scenarios: []assessment.ScenarioResult{{
						ID:       "pipeline.acquire",
						Required: true,
						Outcome:  assessment.OutcomeUnsupported,
						Reason:   unsupported.Error(),
					}},
					Failures: []Failure{{
						Phase: "acquire", Code: "acquisition_unsupported",
						Message: unsupported.Error(), Retryable: false,
					}},
					Trace: acquisitionTrace, Reference: tgt.Reference,
				}, nil
			}
			return nil, targetError("acquire", "acquisition_failed", true, err)
		}
		installed = res

		mounts = append(mounts, installed.Mounts()...)
		policy.Env = installed.Env

		// Detonate on the runtime the dependencies were built for. A Node
		// package installed into a volume is useless inside a Python image:
		// the deps are present but `node` is not.
		if installed.Image != "" {
			policy.Image = installed.Image
		}

		// Node source runs beside its installed node_modules in the read-only
		// dependency volume. This applies even when no compile step was needed;
		// Node does not resolve /deps/app/node_modules for /target/server.js.
		if rewritten := installed.Command(tgt.Reference); rewritten != tgt.Reference {
			p.step(fmt.Sprintf("  acquired runtime at %s", installed.Root))
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

		// The same inventory analysis the probing path runs. Wiring it into
		// only one of the two would mean a poisoned description is caught or
		// missed depending on whether probes happened to be enabled — and the
		// metadata is identical either way. This path is the one a user reaches
		// with probing off, which is exactly when metadata is all there is.
		if findings := toolscan.Analyze(res.Tools); len(findings) > 0 {
			if res.Trace == nil {
				res.Trace = newTrace(tgt.Reference)
			}
			for _, ev := range findings {
				res.Trace.Add(ev)
			}
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

	// Furnish the sandbox before the target starts.
	//
	// An empty home is not a neutral environment, it is an untestable one: a
	// target with nothing to read cannot demonstrate that it reads things it
	// should not. The decoy is writable so a server that stores state under ~
	// still behaves normally, and it is deleted with the scan.
	var den *decoy.Environment
	decoyDir, decoyErr := os.MkdirTemp("", "detonate-decoy-")
	if decoyErr == nil {
		defer os.RemoveAll(decoyDir)
		if planted, plantErr := decoy.Plant(decoyDir, sandbox.ContainerHome); plantErr == nil {
			den = planted
			mounts = append(mounts, sandbox.Mount{
				HostPath:      decoyDir,
				ContainerPath: sandbox.ContainerHome,
				ReadOnly:      false,
			})
		} else {
			decoyErr = plantErr
		}
	}
	if decoyErr != nil {
		// Not fatal: a scan without a decoy is a weaker scan, not a wrong one.
		// It must be visible rather than silent, though, or the report would
		// imply a leak check that never ran.
		p.step("  could not furnish the sandbox decoy; credential-leak checks are disabled")
	}

	// Probing keeps the session open: a tool only reveals what it does when it
	// is called, so the container has to outlive tools/list.
	var err error
	sess, err = mcpdriver.OpenSession(ctx, tgt.Reference, policy, mounts)
	if err != nil {
		return nil, targetError("start", "mcp_start_failed", false, err)
	}

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

	// What the inventory itself says, independent of anything the server does.
	// The metadata was already being collected and rendered; nothing read it
	// until now, which left the highest-leverage MCP attack surface — a
	// description the model obeys and the installer never reads — unexamined.
	//
	// Pure and inventory-only, so it needs no sandbox and cannot be affected by
	// probe ordering. It runs here rather than after probing so that a poisoned
	// description is reported even when probing is skipped entirely.
	for _, ev := range toolscan.Analyze(tools) {
		tr.Add(ev)
	}

	probeable := probe.StringInputToolCount(tools)
	if probeable == 0 {
		p.step(fmt.Sprintf("  %d tool(s) expose no adversarial string-input surface; no payloads sent",
			len(tools)))
	} else {
		p.step(fmt.Sprintf("  probing %d/%d tool(s) with %d adversarial payload(s)...",
			probeable, len(tools), len(probe.Payloads())))
	}

	// The engine attributes probe-phase behaviour to the specific payload and
	// tool that provoked it, and skips tools that need the network (their
	// egress is expected, not a finding). There is deliberately no aggregate
	// re-scan of the whole stderr buffer afterwards: it re-flagged the
	// expected, blocked network noise from every API-backed tool as a critical
	// finding, which turned a clean Notion server into "dangerous".
	var probeOpts []probe.Option
	if den != nil {
		probeOpts = append(probeOpts, probe.WithDecoy(den))
	}
	probeResult := probe.RunWithResults(ctx, sess, tools, 0, probeOpts...)
	for _, ev := range probeResult.Events {
		tr.Add(ev)
	}
	scenarios = append(scenarios, probeResult.Scenarios...)

	return &Report{
		Tools: tools, Trace: tr,
		Scenarios: scenarios, Reference: tgt.Reference,
	}, nil
}

func addTeardownFailure(report *Report, err error) {
	if report == nil || err == nil {
		return
	}
	message := err.Error()
	report.Scenarios = append(report.Scenarios, assessment.ScenarioResult{
		ID:       "pipeline.teardown",
		Required: true,
		Outcome:  assessment.OutcomeTeardownError,
		Reason:   message,
	})
	report.Failures = append(report.Failures, Failure{
		Phase: "teardown", Code: "teardown_failed", Message: message,
		Retryable: true,
	})
}
