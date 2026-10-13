package hook

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func mkRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	g := func(args ...string) {
		t.Helper()
		c := exec.Command("git", args...)
		c.Dir = root
		c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+t.TempDir())
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	g("init", "-q")
	g("config", "user.email", "t@t")
	g("config", "user.name", "t")
	return root
}

func fakeBin(t *testing.T, exit string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mamori-fake")
	if err := os.WriteFile(p, []byte("#!/usr/bin/env sh\nexit "+exit+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func runHook(t *testing.T, p, dir string) error {
	t.Helper()
	c := exec.Command(p)
	c.Dir = dir
	return c.Run()
}

func TestInstallWritesExecutableHook(t *testing.T) {
	p, err := Install(mkRepo(t), "/usr/bin/mamori", false)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o111 == 0 {
		t.Fatal("hook must be executable")
	}
}

func TestInstallRefusesOverwrite(t *testing.T) {
	root := mkRepo(t)
	if _, err := Install(root, "/usr/bin/mamori", false); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(root, "/usr/bin/mamori", false); err == nil {
		t.Fatal("expected error without force")
	}
	if _, err := Install(root, "/usr/bin/mamori", true); err != nil {
		t.Fatalf("force must overwrite: %v", err)
	}
}

func TestInstallOutsideRepoErrors(t *testing.T) {
	if _, err := Install(t.TempDir(), "/usr/bin/mamori", false); err == nil {
		t.Fatal("expected error outside repo")
	}
}

func TestHookBlocksOnFindings(t *testing.T) {
	root := mkRepo(t)
	p, err := Install(root, fakeBin(t, "1"), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := runHook(t, p, root); err == nil {
		t.Fatal("hook must block when checks report findings")
	}
}

func TestHookPassesWhenClean(t *testing.T) {
	root := mkRepo(t)
	p, err := Install(root, fakeBin(t, "0"), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := runHook(t, p, root); err != nil {
		t.Fatalf("hook must pass when clean: %v", err)
	}
}
