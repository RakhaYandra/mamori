package auditor

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/RakhaYandra/mamori/internal/audit"
	"github.com/RakhaYandra/mamori/internal/baseline"
	"github.com/RakhaYandra/mamori/internal/gitinspect"
	"github.com/RakhaYandra/mamori/internal/rules"
	"github.com/RakhaYandra/mamori/internal/scanner"
	"github.com/RakhaYandra/mamori/internal/sshaudit"
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
	// HistoryLimit > 0 enables Git history scan (commits to inspect).
	HistoryLimit int
	// IncludeSSH audits the SSH client config and ~/.ssh directory.
	IncludeSSH bool
	// Custom adds user-supplied secret patterns to the scan.
	Custom []rules.CustomRule
	// Files restricts the scan to explicit paths (e.g. staged files),
	// skipping the directory walk when set.
	Files []string
	// BaselinePath points at a .mamori-baseline file; matching findings
	// are hidden. UpdateBaseline rewrites it from the current findings.
	BaselinePath   string
	UpdateBaseline bool
	// SSHConfigPath overrides ~/.ssh/config (empty = default).
	SSHConfigPath string
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
	var walked scanner.WalkResult
	if len(opts.Files) > 0 {
		for _, p := range opts.Files {
			fi, err := os.Lstat(p)
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			bin, berr := scanner.IsBinary(p)
			if berr != nil {
				walked.Partial = append(walked.Partial, fmt.Errorf("%s: %w", p, berr))
				continue
			}
			if opts.MaxBytes > 0 && fi.Size() > opts.MaxBytes {
				walked.Skipped = append(walked.Skipped, p)
				continue
			}
			walked.Files = append(walked.Files, scanner.File{Path: p, Size: fi.Size(), Binary: bin})
		}
	} else {
		var err error
		walked, err = scanner.Walk(opts.Target, scanner.WalkOptions{
			MaxBytes:   opts.MaxBytes,
			ScanHidden: true,
			Excludes:   opts.Excludes,
		})
		if err != nil {
			return Result{}, err
		}
	}
	res := Result{Target: opts.Target, Skipped: walked.Skipped}
	res.Partial = append(res.Partial, walked.Partial...)

	hits, perr := scanner.ScanSecretsWith(walked.Files, opts.MaxBytes, opts.Custom)
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

	// Git exposure: tracked/staged sensitive files plus capped history.
	// (ruleID, base name) pairs already found in the work tree are not
	// repeated as history-only.
	worktree := map[string]bool{}
	for _, f := range res.Findings {
		worktree[f.RuleID+"\x00"+filepath.Base(f.Path)] = true
	}
	if ghits, gerr := gitinspect.TrackedSensitive(opts.Target); gerr == nil {
		for _, h := range ghits {
			ev := "State: " + h.State
			res.Findings = append(res.Findings, audit.NewFinding(h.RuleID, "git",
				h.Severity, titleOf(opts.Titles, h.RuleID),
				filepath.Join(h.Repo, h.File), 0, ev, h.Recommendation))
		}
	} else {
		res.Partial = append(res.Partial, gerr)
	}
	if opts.HistoryLimit > 0 {
		if hhits, herr := gitinspect.ScanHistory(opts.Target, opts.HistoryLimit, opts.MaxBytes); herr == nil {
			for _, h := range hhits {
				if worktree[h.RuleID+"\x00"+filepath.Base(h.File)] {
					continue
				}
				ev := "State: history-only"
				if h.Masked != "" {
					ev += " Value: " + h.Masked
				}
				res.Findings = append(res.Findings, audit.NewFinding(h.RuleID, "git",
					h.Severity, titleOf(opts.Titles, h.RuleID),
					filepath.Join(h.Repo, h.File), 0, ev, h.Recommendation))
			}
		} else {
			res.Partial = append(res.Partial, herr)
		}
	}

	// SSH client config plus ~/.ssh directory permissions.
	if opts.IncludeSSH {
		home, herr := os.UserHomeDir()
		cfgPath := opts.SSHConfigPath
		if cfgPath == "" && herr == nil {
			cfgPath = filepath.Join(home, ".ssh", "config")
		}
		if shits, serr := sshaudit.AuditFile(cfgPath); serr == nil {
			for _, h := range shits {
				ev := "Scope: " + h.Scope
				res.Findings = append(res.Findings, audit.NewFinding(h.RuleID, "ssh",
					h.Severity, titleOf(opts.Titles, h.RuleID), h.File, 0, ev, h.Recommendation))
			}
		}
		if herr == nil {
			if dh, derr := scanner.CheckPath(filepath.Join(home, ".ssh")); derr == nil {
				for _, h := range dh {
					ev := fmt.Sprintf("Mode: %04o Expected: %s", h.Mode.Perm(), h.Expected)
					res.Findings = append(res.Findings, audit.NewFinding(h.RuleID, h.Category,
						h.Severity, titleOf(opts.Titles, h.RuleID), h.Path, 0, ev, h.Recommendation))
				}
			}
		}
	}

	if opts.UpdateBaseline && opts.BaselinePath != "" {
		if berr := baseline.Update(opts.BaselinePath, res.Findings, ""); berr != nil {
			res.Partial = append(res.Partial, berr)
		}
	} else if opts.BaselinePath != "" {
		if bl, berr := baseline.Load(opts.BaselinePath); berr != nil {
			res.Partial = append(res.Partial, berr)
		} else {
			res.Findings = bl.Suppress(res.Findings)
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
