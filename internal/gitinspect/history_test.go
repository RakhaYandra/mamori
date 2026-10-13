package gitinspect

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const histKey = "sk_live_9f2Kq7ZmX4vB8tYw6s7f2a"

func mkHistRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		c := exec.Command("git", args...)
		c.Dir = root
		c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+t.TempDir())
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	git("config", "user.email", "t@t")
	git("config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("const K = \""+histKey+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", "app.go")
	git("commit", "-qm", "oops")
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("const K = \"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("commit", "-qam", "remove")
	return root
}

func TestHistoryFindsRemovedSecret(t *testing.T) {
	hits, err := ScanHistory(mkHistRepo(t), 100, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range hits {
		if h.RuleID == "secret.api-key" && h.State == "history-only" {
			found = true
		}
		if h.File == "" {
			t.Fatalf("history hit needs file: %+v", h)
		}
	}
	if !found {
		t.Fatalf("missing history-only api-key in %+v", hits)
	}
}

func TestHistoryLimitZeroScansNothing(t *testing.T) {
	hits, err := ScanHistory(mkHistRepo(t), 0, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("want none, got %+v", hits)
	}
}

func TestHistoryNonRepoEmpty(t *testing.T) {
	hits, err := ScanHistory(t.TempDir(), 100, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("want empty, got %+v", hits)
	}
}
