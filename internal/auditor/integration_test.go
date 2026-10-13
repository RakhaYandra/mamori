package auditor_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/RakhaYandra/mamori/internal/auditor"
)

func g(t *testing.T, dir string, args ...string) {
	t.Helper()
	c := exec.Command("git", args...)
	c.Dir = dir
	c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+t.TempDir())
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func mkGitRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	g(t, root, "init", "-q")
	g(t, root, "config", "user.email", "t@t")
	g(t, root, "config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("K=V\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "leak.go"), []byte("const K = \"sk_live_9f2Kq7ZmX4vB8tYw6s7f2a\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g(t, root, "add", ".env", "leak.go")
	g(t, root, "commit", "-qm", "oops")
	if err := os.WriteFile(filepath.Join(root, "leak.go"), []byte("const K = \"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g(t, root, "commit", "-qam", "clean")
	return root
}

func TestRunIncludesGitFindings(t *testing.T) {
	res, err := auditor.Run(auditor.Options{Target: mkGitRepo(t), Titles: map[string]string{}, MaxBytes: 1 << 20, HistoryLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, f := range res.Findings {
		if f.Category == "git" {
			states[f.RuleID] = f.Evidence
		}
	}
	if _, ok := states["git.env-tracked"]; !ok {
		t.Fatalf("missing git.env-tracked in %+v", res.Findings)
	}
	foundHistory := false
	for _, f := range res.Findings {
		if f.RuleID == "secret.api-key" && f.Category == "git" {
			foundHistory = true
		}
	}
	if !foundHistory {
		t.Fatalf("missing history-only api-key in %+v", res.Findings)
	}
}

func TestHistoryOffByDefault(t *testing.T) {
	res, err := auditor.Run(auditor.Options{Target: mkGitRepo(t), Titles: map[string]string{}, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.Category == "git" && f.RuleID == "secret.api-key" {
			t.Fatalf("history must be off by default: %+v", f)
		}
	}
}

func TestRunIncludesSSHFindings(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	if err := os.WriteFile(cfg, []byte("Host *\n  ForwardAgent yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := auditor.Run(auditor.Options{Target: dir, Titles: map[string]string{}, MaxBytes: 100, IncludeSSH: true, SSHConfigPath: cfg})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range res.Findings {
		if f.Category == "ssh" && f.RuleID == "ssh.forward-agent" {
			found = true
		}
		if f.Severity == "" || f.Title == "" {
			t.Fatalf("finding needs severity+title: %+v", f)
		}
	}
	if !found {
		t.Fatalf("missing ssh.forward-agent in %+v", res.Findings)
	}
}
