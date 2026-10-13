// Package gitinspect reads Git state via the Git CLI allowlist.
// Read-only: status, ls-files, diff, log, show, rev-parse. No shell.
package gitinspect

import (
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/RakhaYandra/mamori/internal/audit"
)

// GitHit is one redacted Git exposure finding.
type GitHit struct {
	Repo           string
	File           string
	State          string // tracked | staged | untracked | history-only
	RuleID         string
	Severity       audit.Severity
	Masked         string // redacted evidence, "" when nothing safe to show
	Recommendation string
}

func runGit(dir string, args ...string) (string, error) {
	c := exec.Command("git", args...)
	c.Dir = dir
	out, err := c.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// IsRepo reports whether path sits inside a Git work tree.
func IsRepo(path string) bool {
	out, err := runGit(path, "rev-parse", "--is-inside-work-tree")
	return err == nil && strings.TrimSpace(out) == "true"
}

func isEnvName(base string) bool {
	if audit.IsEnvTemplate(base) {
		return false
	}
	return base == ".env" || strings.HasPrefix(base, ".env.")
}

// StagedFiles lists absolute paths of files staged in the index.
// Outside a repo it returns an empty list.
func StagedFiles(path string) ([]string, error) {
	if !IsRepo(path) {
		return nil, nil
	}
	top, err := runGit(path, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	top = strings.TrimSpace(top)
	out, err := runGit(path, "diff", "--cached", "--name-only")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range strings.Split(out, "\n") {
		if f = strings.TrimSpace(f); f != "" {
			files = append(files, filepath.Join(top, f))
		}
	}
	return files, nil
}

func isKeyName(base string) bool {
	if strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key") {
		return true
	}
	switch base {
	case "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa":
		return true
	}
	return false
}

// TrackedSensitive lists sensitive files that are tracked or staged.
// Outside a repo it returns no hits and no error.
func TrackedSensitive(path string) ([]GitHit, error) {
	if !IsRepo(path) {
		return nil, nil
	}
	top, err := runGit(path, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	top = strings.TrimSpace(top)
	var hits []GitHit

	tracked, err := runGit(path, "ls-files")
	if err != nil {
		return nil, err
	}
	committed := map[string]bool{}
	if committedOut, err := runGit(path, "ls-tree", "-r", "HEAD", "--name-only"); err == nil {
		for _, f := range strings.Split(committedOut, "\n") {
			if f = strings.TrimSpace(f); f != "" {
				committed[f] = true
			}
		}
	}
	add := func(f, state, rule string, sev audit.Severity, rec string) {
		hits = append(hits, GitHit{Repo: top, File: f, State: state,
			RuleID: rule, Severity: sev, Recommendation: rec})
	}
	for _, f := range strings.Split(tracked, "\n") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		// In index but not in HEAD: staged for the next commit.
		state := "tracked"
		if !committed[f] {
			state = "staged"
		}
		base := filepath.Base(f)
		switch {
		case isEnvName(base):
			add(f, state, "git.env-tracked", audit.SeverityHigh,
				"Remove it from tracking and rotate exposed credentials.")
		case isKeyName(base):
			add(f, state, "git.key-tracked", audit.SeverityHigh,
				"Remove the key from the repository and rotate it.")
		}
	}
	return hits, nil
}
