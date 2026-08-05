// Package scenario defines the portable contract for one Detonate test case.
//
// A contract describes the intent and safety boundary of a test before any
// target code runs. It is deliberately independent of MCP SDK types, Docker,
// and an LLM provider so the same corpus can drive deterministic probes,
// skill workflows, prompt checks, and future agentic replays.
package scenario

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// TargetKind identifies the artifact being tested.
type TargetKind string

const (
	TargetMCP    TargetKind = "mcp"
	TargetSkill  TargetKind = "skill"
	TargetPrompt TargetKind = "prompt"
)

// Mode says whether a scenario can affect Detonate's deterministic verdict or
// is an optional model-specific observation.
type Mode string

const (
	ModeDeterministic Mode = "deterministic"
	ModeAgentic       Mode = "agentic"
)

// Runtime names a pinned sandbox profile. It is a compatibility declaration,
// not permission to execute directly on the host.
type Runtime string

const (
	RuntimeAuto    Runtime = "auto"
	RuntimeNode    Runtime = "node"
	RuntimePython  Runtime = "python"
	RuntimeGo      Runtime = "go"
	RuntimeSystem  Runtime = "system"
	RuntimeBrowser Runtime = "browser"
)

// Duration serializes as a human-readable duration (for example, "20s") so
// JSON and YAML scenario files behave the same on every supported host.
type Duration time.Duration

func (d Duration) Value() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}
	return d.parse(text)
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a scalar string")
	}
	return d.parse(value.Value)
}

func (d *Duration) parse(text string) error {
	parsed, err := time.ParseDuration(text)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", text, err)
	}
	*d = Duration(parsed)
	return nil
}

// Expectation is the deterministic oracle for a scenario. A runner records
// the observed calls and effects; assessment decides the final risk and
// completeness result from that evidence.
type Expectation struct {
	MustCall    []string `json:"must_call,omitempty" yaml:"must_call,omitempty"`
	MustNotCall []string `json:"must_not_call,omitempty" yaml:"must_not_call,omitempty"`
}

// Contract is a versioned, bounded test definition. It stores only references
// to fixtures and credentials; it must never embed secrets.
type Contract struct {
	ID             string      `json:"id" yaml:"id"`
	TargetKind     TargetKind  `json:"target_kind" yaml:"target_kind"`
	Trigger        string      `json:"trigger" yaml:"trigger"`
	Required       bool        `json:"required" yaml:"required"`
	Mode           Mode        `json:"mode" yaml:"mode"`
	Runtime        Runtime     `json:"runtime" yaml:"runtime"`
	Fixtures       []string    `json:"fixtures,omitempty" yaml:"fixtures,omitempty"`
	AllowedTools   []string    `json:"allowed_tools,omitempty" yaml:"allowed_tools,omitempty"`
	ForbiddenTools []string    `json:"forbidden_tools,omitempty" yaml:"forbidden_tools,omitempty"`
	Expectation    Expectation `json:"expectation,omitempty" yaml:"expectation,omitempty"`
	MaxTurns       int         `json:"max_turns,omitempty" yaml:"max_turns,omitempty"`
	Timeout        Duration    `json:"timeout,omitempty" yaml:"timeout,omitempty"`
}

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]*(/[a-z][a-z0-9._-]*)*$`)

// Validate rejects ambiguous or unsafe scenario definitions before a runner
// can act on them.
func (c Contract) Validate() error {
	if !idPattern.MatchString(c.ID) {
		return fmt.Errorf("scenario ID %q must contain lowercase stable path segments", c.ID)
	}
	if !validTargetKind(c.TargetKind) {
		return fmt.Errorf("scenario %q has invalid target kind %q", c.ID, c.TargetKind)
	}
	if strings.TrimSpace(c.Trigger) == "" {
		return fmt.Errorf("scenario %q has no trigger", c.ID)
	}
	if c.Mode != ModeDeterministic && c.Mode != ModeAgentic {
		return fmt.Errorf("scenario %q has invalid mode %q", c.ID, c.Mode)
	}
	if !validRuntime(c.Runtime) {
		return fmt.Errorf("scenario %q has invalid runtime %q", c.ID, c.Runtime)
	}
	if c.MaxTurns < 0 {
		return fmt.Errorf("scenario %q has negative max turns", c.ID)
	}
	if c.Timeout.Value() < 0 {
		return fmt.Errorf("scenario %q has negative timeout", c.ID)
	}
	if err := validatePaths(c.ID, c.Fixtures); err != nil {
		return err
	}
	if err := disjoint(c.ID, "allowed tools", c.AllowedTools, "forbidden tools", c.ForbiddenTools); err != nil {
		return err
	}
	if err := subset(c.ID, "must call", c.Expectation.MustCall, c.AllowedTools); err != nil {
		return err
	}
	if err := disjoint(c.ID, "must call", c.Expectation.MustCall, "must not call", c.Expectation.MustNotCall); err != nil {
		return err
	}
	return nil
}

// MCPToolID and SkillScriptID centralize IDs already emitted by the existing
// engine. Keeping them stable makes old reports comparable while new scenario
// contracts are introduced incrementally.
func MCPToolID(name string) string { return "mcp.tool/" + name }

func SkillScriptID(path string) string {
	// filepath.ToSlash only converts the separator of the current host. Scan
	// bundles may be created on Windows and replayed on Linux (or the reverse),
	// so normalize both spellings explicitly.
	return "skill.script/" + strings.ReplaceAll(filepath.ToSlash(path), "\\", "/")
}

func validTargetKind(kind TargetKind) bool {
	return kind == TargetMCP || kind == TargetSkill || kind == TargetPrompt
}

func validRuntime(runtime Runtime) bool {
	switch runtime {
	case RuntimeAuto, RuntimeNode, RuntimePython, RuntimeGo, RuntimeSystem, RuntimeBrowser:
		return true
	default:
		return false
	}
}

func validatePaths(id string, paths []string) error {
	for _, path := range paths {
		portable := strings.ReplaceAll(path, "\\", string(filepath.Separator))
		clean := filepath.Clean(portable)
		if path == "" || filepath.IsAbs(path) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("scenario %q has fixture outside its fixture root: %q", id, path)
		}
	}
	return nil
}

func disjoint(id, leftName string, left []string, rightName string, right []string) error {
	leftSet := stringSet(left)
	for _, value := range right {
		if _, ok := leftSet[value]; ok {
			return fmt.Errorf("scenario %q declares %q in both %s and %s", id, value, leftName, rightName)
		}
	}
	return nil
}

func subset(id, name string, values, allowed []string) error {
	if len(values) == 0 || len(allowed) == 0 {
		return nil
	}
	allowedSet := stringSet(allowed)
	for _, value := range values {
		if _, ok := allowedSet[value]; !ok {
			return fmt.Errorf("scenario %q expects %s tool %q that is not allowlisted", id, name, value)
		}
	}
	return nil
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

// NormalizedTools returns a sorted copy for stable report and test output.
func NormalizedTools(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
