package cli

import (
	"fmt"

	"github.com/m4vic/detonate/internal/quality"
)

// printQuality renders the design and cost sections.
//
// Printed after the security verdict and scored separately from it. The
// separation is the point: a reader who has just been told a tool leaked a
// credential must not have to scroll past six notes about description length
// to find out, and a CI pipeline must never fail because a parameter was
// undocumented. Nothing in here touches the exit code.
func (a *App) printQuality(report quality.Report) {
	if len(report.Design) == 0 && report.Cost.Total == 0 {
		return
	}

	const rule = "  ----------------------------------------------------------------"

	if len(report.Design) > 0 {
		fmt.Fprintf(a.Stdout, "\n%s\n", rule)
		fmt.Fprintf(a.Stdout, "  DESIGN  (%d note(s), does not affect the exit code)\n", len(report.Design))
		fmt.Fprintf(a.Stdout, "%s\n", rule)

		// Warnings first: a fault an agent will trip over outranks a
		// preference, and ordering by severity is the cheapest way to make a
		// list of notes worth reading top-down.
		for _, level := range []quality.Level{quality.LevelWarning, quality.LevelSuggestion} {
			for _, note := range report.Design {
				if note.Level != level {
					continue
				}
				subject := ""
				if note.Subject != "" {
					subject = fmt.Sprintf(" [%s]", note.Subject)
				}
				fmt.Fprintf(a.Stdout, "\n  %s%s: %s\n", level, subject, note.Summary)
				if note.Detail != "" {
					fmt.Fprintf(a.Stdout, "     %s\n", note.Detail)
				}
			}
		}
	}

	if report.Cost.Total > 0 {
		fmt.Fprintf(a.Stdout, "\n%s\n", rule)
		fmt.Fprintln(a.Stdout, "  COST")
		fmt.Fprintf(a.Stdout, "%s\n", rule)
		fmt.Fprintf(a.Stdout, "  ~%d tokens %s (estimated)\n", report.Cost.Total, report.Cost.Unit)

		// Only the heaviest few. The whole list is in the JSON report for
		// anyone who wants it; on a terminal it would bury the total.
		const show = 5
		for i, item := range report.Cost.Items {
			if i >= show {
				fmt.Fprintf(a.Stdout, "    ...and %d more\n", len(report.Cost.Items)-show)
				break
			}
			fmt.Fprintf(a.Stdout, "    %-32s ~%d tokens\n", item.Name, item.Tokens)
		}
	}
}
