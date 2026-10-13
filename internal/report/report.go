// Package report renders sanitized findings. It never sees raw secrets:
// scanners mask at detection, and inputs must already be redacted.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/RakhaYandra/mamori/internal/audit"
	"github.com/RakhaYandra/mamori/internal/redact"
)

// SchemaVersion versions the JSON report format.
const SchemaVersion = "v1"

var categoryNames = map[string]string{
	"secret":      "Secrets",
	"permissions": "Permissions",
	"git":         "Git Exposure",
	"ssh":         "SSH",
}

var severitiesDesc = []audit.Severity{
	audit.SeverityCritical, audit.SeverityHigh, audit.SeverityMedium,
	audit.SeverityLow, audit.SeverityInfo,
}

// Summary counts findings by severity and category.
type Summary struct {
	Total      int
	BySeverity map[audit.Severity]int
	ByCategory map[string]int
}

// Summarize counts findings.
func Summarize(fs []audit.Finding) Summary {
	s := Summary{BySeverity: map[audit.Severity]int{}, ByCategory: map[string]int{}}
	for _, f := range fs {
		s.Total++
		s.BySeverity[f.Severity]++
		s.ByCategory[f.Category]++
	}
	return s
}

// RenderTerminal writes the human-readable audit summary plus finding details.
func RenderTerminal(w io.Writer, target string, fs []audit.Finding, quiet bool) error {
	fs = redact.SanitizeAll(fs, nil)
	s := Summarize(fs)
	fmt.Fprintln(w, "Mamori Security Audit")
	fmt.Fprintf(w, "Target: %s\n\n", target)
	cats := make([]string, 0, len(s.ByCategory))
	for c := range s.ByCategory {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		name := categoryNames[c]
		if name == "" {
			name = c
		}
		fmt.Fprintf(w, "  %-15s %d findings\n", name, s.ByCategory[c])
	}
	fmt.Fprintln(w)
	for _, sev := range severitiesDesc {
		if n := s.BySeverity[sev]; n > 0 {
			fmt.Fprintf(w, "  %-10s %d\n", strings.ToUpper(string(sev)), n)
		}
	}
	fmt.Fprintf(w, "\n  Overall: %d findings\n", s.Total)
	if quiet {
		return nil
	}
	fmt.Fprintln(w)
	for _, f := range fs {
		fmt.Fprintf(w, "%s  %s  %s\n", strings.ToUpper(string(f.Severity)), f.RuleID, f.Title)
		if f.Path != "" {
			fmt.Fprintf(w, "      File: %s\n", f.Path)
		}
		if f.Line > 0 {
			fmt.Fprintf(w, "      Line: %d\n", f.Line)
		}
		if f.Evidence != "" {
			fmt.Fprintf(w, "      Value: %s\n", f.Evidence)
		}
		fmt.Fprintf(w, "      Action: %s\n", f.Recommendation)
	}
	fmt.Fprintln(w, "\nRun `mamori report` for details.")
	return nil
}

type jsonReport struct {
	SchemaVersion string          `json:"schema_version"`
	Target        string          `json:"target"`
	Summary       map[string]int  `json:"summary"`
	Findings      []audit.Finding `json:"findings"`
}

// RenderJSON writes the versioned JSON report.
func RenderJSON(w io.Writer, target string, fs []audit.Finding) error {
	fs = redact.SanitizeAll(fs, nil)
	summary := map[string]int{"total": len(fs)}
	for _, f := range fs {
		summary[string(f.Severity)]++
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(jsonReport{SchemaVersion: SchemaVersion, Target: target, Summary: summary, Findings: fs})
}
