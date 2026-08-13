package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/m4vic/detonate/internal/termsafe"
)

const (
	colorAuto   = "auto"
	colorAlways = "always"
	colorNever  = "never"

	ansiReset   = "\x1b[0m"
	ansiBold    = "\x1b[1m"
	ansiDim     = "\x1b[2m"
	ansiRed     = "\x1b[31m"
	ansiGreen   = "\x1b[32m"
	ansiYellow  = "\x1b[33m"
	ansiMagenta = "\x1b[35m"
	ansiCyan    = "\x1b[36m"
)

func validColorMode(mode string) bool {
	return mode == colorAuto || mode == colorAlways || mode == colorNever
}

func writerIsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// configureColor resolves policy once per invocation. Machine formats always
// disable ANSI, even when --color=always was supplied: a valid JSON/SARIF
// stream is a stronger contract than decoration.
func (a *App) configureColor(mode, format string) error {
	if mode == "" {
		mode = colorAuto
	}
	if !validColorMode(mode) {
		return fmt.Errorf("unknown color mode %q; use auto, always, or never", mode)
	}
	a.colorMode = mode
	a.colorEnabled = format != "json" && format != "sarif" &&
		mode != colorNever && os.Getenv("NO_COLOR") == "" &&
		(mode == colorAlways || writerIsTerminal(a.Stdout))
	return nil
}

func (a *App) paint(code, value string) string {
	if !a.colorEnabled {
		return value
	}
	return code + value + ansiReset
}

func (a *App) heading(value string) string { return a.paint(ansiBold+ansiCyan, value) }
func (a *App) success(value string) string { return a.paint(ansiBold+ansiGreen, value) }
func (a *App) warning(value string) string { return a.paint(ansiBold+ansiYellow, value) }
func (a *App) danger(value string) string  { return a.paint(ansiBold+ansiRed, value) }
func (a *App) active(value string) string  { return a.paint(ansiBold+ansiMagenta, value) }
func (a *App) muted(value string) string   { return a.paint(ansiDim, value) }

func (a *App) label(name string) string {
	return a.heading(fmt.Sprintf("  %-10s", strings.ToUpper(name)))
}

func (a *App) metadata(name, value string) {
	fmt.Fprintf(a.Stdout, "%s %s\n", a.label(name), terminalSafe(value))
}

// terminalSafe prevents target-controlled names, descriptions, commands, and
// evidence from injecting ANSI styling or cursor movement that could make
// target output impersonate scanner-authored status.
func terminalSafe(value string) string {
	return termsafe.Clean(value)
}

func (a *App) section(name string) {
	fmt.Fprintf(a.Stdout, "\n%s\n", a.heading("== "+strings.ToUpper(name)+" =="))
}

func (a *App) promptText() string {
	return a.paint(ansiBold+ansiCyan, "detonate> ")
}

func (a *App) riskText(risk string) string {
	switch risk {
	case "dangerous":
		return a.danger(risk)
	case "suspicious":
		return a.warning(risk)
	case "no_findings":
		return a.success(risk)
	default:
		return a.warning(risk)
	}
}

func (a *App) completenessText(value string) string {
	switch value {
	case "complete":
		return a.success(value)
	case "failed":
		return a.danger(value)
	default:
		return a.warning(value)
	}
}
