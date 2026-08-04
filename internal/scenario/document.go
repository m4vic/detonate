package scenario

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// SchemaV1 is the first stable scenario-file format. JSON is accepted because
// it is a YAML subset; YAML is friendlier for hand-authored fixture corpora.
const SchemaV1 = "detonate.scenario/v1"

// Document is the portable scenario corpus exchanged by the Go harness and
// fixtures written in other languages.
type Document struct {
	Schema    string     `json:"schema" yaml:"schema"`
	Scenarios []Contract `json:"scenarios" yaml:"scenarios"`
}

// LoadFile loads one JSON or YAML scenario document and validates the complete
// corpus before anything can execute.
func LoadFile(path string) (Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, fmt.Errorf("read scenario file %q: %w", path, err)
	}
	var document Document
	if err := yaml.Unmarshal(data, &document); err != nil {
		return Document{}, fmt.Errorf("parse scenario file %q: %w", path, err)
	}
	if err := document.Validate(); err != nil {
		return Document{}, err
	}
	return document, nil
}

// Validate ensures the corpus has a stable schema and contains no duplicate
// IDs. A runner can therefore use IDs as report keys without accidental merge.
func (d Document) Validate() error {
	if d.Schema != SchemaV1 {
		return fmt.Errorf("scenario document schema is %q, want %q", d.Schema, SchemaV1)
	}
	if len(d.Scenarios) == 0 {
		return fmt.Errorf("scenario document contains no scenarios")
	}
	seen := make(map[string]struct{}, len(d.Scenarios))
	for i, scenario := range d.Scenarios {
		if err := scenario.Validate(); err != nil {
			return fmt.Errorf("scenario %d: %w", i, err)
		}
		if _, ok := seen[scenario.ID]; ok {
			return fmt.Errorf("duplicate scenario ID %q", scenario.ID)
		}
		seen[scenario.ID] = struct{}{}
	}
	return nil
}
