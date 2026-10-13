package auditor

import (
	"fmt"
	"os"

	"github.com/RakhaYandra/mamori/internal/audit"
	"github.com/RakhaYandra/mamori/internal/scanner"
)

// Options scopes one audit run.
type Options struct {
	Target      string
	Titles      map[string]string // rule ID -> title (from bundled/custom rules)
	MinSeverity audit.Severity    // empty means show all
	Format      string
	Excludes    []string
	Quiet       bool
	MaxBytes    int64
	// IncludeHomeSSH also checks ~/.ssh even when outside Target.
	// Off in tests to avoid touching the real home directory.
	IncludeHomeSSH bool
}

// Result is one completed audit.
type Result struct {
	Target   string
	Findings []audit.Finding
	Partial  []error
	Skipped  []string
}

// Exit codes: 0 clean, 1 findings, 3 incomplete. Findings outrank partial:
// a scan that found risks reports 1 even with partial failures.
func ExitCode(r Result) int {
	if len(r.Findings) > 0 {
		return 1
	}
	if len(r.Partial) > 0 {
		return 3
	}
	return 0
}

func titleOf(titles map[string]string, ruleID string) string {
	if t, ok := titles[ruleID]; ok {
		return t
	}
	return ruleID
}

// Run walks the target and applies secret + permission scanners.
func Run(opts Options) (Result, error) {
	if opts.Target == "" {
		opts.Target = "."
	}
	walked, err := scanner.Walk(opts.Target, scanner.WalkOptions{
		MaxBytes:   opts.MaxBytes,
		ScanHidden: true,
		Excludes:   opts.Excludes,
	})
	if err != nil {
		return Result{}, err
	}
	res := Result{Target: opts.Target, Skipped: walked.Skipped}
	res.Partial = append(res.Partial, walked.Partial...)

	hits, perr := scanner.ScanSecrets(walked.Files, opts.MaxBytes)
	res.Partial = append(res.Partial, perr...)
	for _, h := range hits {
		f := audit.NewFinding(h.RuleID, h.Category, h.Severity, titleOf(opts.Titles, h.RuleID),
			h.File.Path, h.Line, h.Masked, h.Recommendation)
		res.Findings = append(res.Findings, f)
	}

	phits, perr := scanner.ScanPermissions(walked.Files)
	res.Partial = append(res.Partial, perr...)
	for _, h := range phits {
		ev := fmt.Sprintf("Mode: %04o Expected: %s", h.Mode.Perm(), h.Expected)
		f := audit.NewFinding(h.RuleID, h.Category, h.Severity, titleOf(opts.Titles, h.RuleID),
			h.Path, 0, ev, h.Recommendation)
		res.Findings = append(res.Findings, f)
	}

	// The ~/.ssh directory is outside most targets; check it when asked.
	if opts.IncludeHomeSSH {
		if home, herr := os.UserHomeDir(); herr == nil {
			if dh, derr := scanner.CheckPath(home + "/.ssh"); derr == nil {
				for _, h := range dh {
					ev := fmt.Sprintf("Mode: %04o Expected: %s", h.Mode.Perm(), h.Expected)
					res.Findings = append(res.Findings, audit.NewFinding(h.RuleID, h.Category,
						h.Severity, titleOf(opts.Titles, h.RuleID), h.Path, 0, ev, h.Recommendation))
				}
			}
		}
	}

	if opts.MinSeverity != "" {
		min := opts.MinSeverity
		kept := res.Findings[:0]
		for _, f := range res.Findings {
			if f.Severity.AtLeast(min) {
				kept = append(kept, f)
			}
		}
		res.Findings = kept
	}
	return res, nil
}
