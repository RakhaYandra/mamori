// Package hook installs a pre-commit gate that runs mamori on staged files.
// The hook script is static content: no user data is interpolated into it,
// and findings print through mamori's redacted renderers only.
package hook

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const hookBody = `#!/usr/bin/env sh
# Installed by ` + "`mamori hook install`" + `. Blocks commits with staged secrets.
BIN="%s"
"$BIN" secrets --staged --quiet
s=$?
"$BIN" git --staged --quiet
g=$?
if [ "$s" -eq 1 ] || [ "$g" -eq 1 ]; then
  echo "mamori: staged findings detected; commit blocked." >&2
  exit 1
fi
exit 0
`

// Install writes .git/hooks/pre-commit in the repo containing path.
// binPath is the mamori binary to invoke. Without force, an existing
// hook is left alone and an error is returned.
func Install(path, binPath string, force bool) (string, error) {
	top, err := repoTop(path)
	if err != nil {
		return "", err
	}
	hookPath := filepath.Join(top, ".git", "hooks", "pre-commit")
	if _, err := os.Lstat(hookPath); err == nil && !force {
		return "", fmt.Errorf("hook exists at %s (use --force)", hookPath)
	}
	body := fmt.Sprintf(hookBody, binPath)
	if err := os.WriteFile(hookPath, []byte(body), 0o755); err != nil {
		return "", fmt.Errorf("write hook: %w", err)
	}
	return hookPath, nil
}

func repoTop(path string) (string, error) {
	c := exec.Command("git", "rev-parse", "--show-toplevel")
	c.Dir = path
	out, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("not a git repository: %s", path)
	}
	return strings.TrimSpace(string(out)), nil
}
