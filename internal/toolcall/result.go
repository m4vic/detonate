// Package toolcall contains the protocol-neutral representation of one MCP
// tool result. It keeps every content block and structured output intact so
// detectors do not silently become text-only.
package toolcall

import (
	"bytes"
	"encoding/json"
)

// ContentBlock is one MCP content item in its original JSON representation.
type ContentBlock struct {
	Type string          `json:"type"`
	Raw  json.RawMessage `json:"raw"`
}

// Result distinguishes a tool-declared error from a transport/protocol error.
// IsError is part of a valid MCP response and must not be returned as a Go
// error by the transport adapter.
type Result struct {
	Content           []ContentBlock  `json:"content"`
	StructuredContent json.RawMessage `json:"structured_content,omitempty"`
	IsError           bool            `json:"is_error"`
}

// SearchableText returns a lossless JSON view for deterministic detectors.
// It includes text, images/audio metadata, embedded resources, links, and
// structured output instead of dropping everything except TextContent.
func (r Result) SearchableText() string {
	var buf bytes.Buffer
	for _, block := range r.Content {
		buf.Write(block.Raw)
		buf.WriteByte('\n')
	}
	if len(r.StructuredContent) > 0 {
		buf.Write(r.StructuredContent)
	}
	return buf.String()
}
