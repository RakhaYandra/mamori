package gitinspect

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func mkRepo(t *testing.T) string {
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
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("K=V\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package m\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "id_rsa"), []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", ".env", "main.go")
	git("commit", "-qm", "init")
	if err := os.WriteFile(filepath.Join(root, "staged.pem"), []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", "staged.pem")
	return root
}

func TestTrackedFindsEnv(t *testing.T) {
	hits, err := TrackedSensitive(mkRepo(t))
	if err != nil {
		t.Fatal(err)
	}
	byRule := map[string]string{}
	for _, h := range hits {
		byRule[h.RuleID] = h.State
	}
	if byRule["git.env-tracked"] != "tracked" {
		t.Fatalf("hits: %+v", hits)
	}
	if byRule["git.key-tracked"] != "staged" {
		t.Fatalf("staged key missing: %+v", hits)
	}
}

func TestNonRepoIsEmpty(t *testing.T) {
	hits, err := TrackedSensitive(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("want empty, got %+v", hits)
	}
}
