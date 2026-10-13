package gitinspect

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/RakhaYandra/mamori/internal/scanner"
)

// ScanHistory scans up to limit commits for secrets, including ones removed
// from the work tree. Findings are labeled history-only. Blobs never touch
// disk; values are masked at read time.
func ScanHistory(path string, limit int, maxBytes int64) ([]GitHit, error) {
	if limit <= 0 || !IsRepo(path) {
		return nil, nil
	}
	top, err := runGit(path, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	top = strings.TrimSpace(top)
	logOut, err := runGit(path, "log", fmt.Sprintf("-n%d", limit), "--format=%H")
	if err != nil {
		return nil, err
	}
	var hits []GitHit
	seen := map[string]bool{}
	for _, sha := range strings.Fields(logOut) {
		filesOut, err := runGit(path, "diff-tree", "--no-commit-id", "--name-only", "-r", "--root", sha)
		if err != nil {
			return nil, err
		}
		for _, f := range strings.Split(filesOut, "\n") {
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}
			blob, err := runGit(path, "show", sha+":"+f)
			if err != nil || int64(len(blob)) > maxBytes && maxBytes > 0 {
				continue
			}
			if strings.ContainsRune(blob, 0) {
				continue
			}
			line := 0
			sc := bufio.NewScanner(bytes.NewBufferString(blob))
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			for sc.Scan() {
				line++
				ruleID, sev, masked, rec, ok := scanner.CheckSecretLine(sc.Text())
				if !ok {
					continue
				}
				key := ruleID + "\x00" + f
				if seen[key] {
					continue
				}
				seen[key] = true
				hits = append(hits, GitHit{Repo: top, File: f, State: "history-only",
					RuleID: ruleID, Severity: sev, Masked: masked,
					Recommendation: rec + " Rotate it: history keeps the value."})
			}
		}
	}
	return hits, nil
}
