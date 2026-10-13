package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCompletion(t *testing.T, shell string) (string, error) {
	t.Helper()
	root := NewRootCmd("v0-test")
	var b strings.Builder
	root.SetOut(&b)
	root.SetErr(&b)
	root.SetArgs([]string{"completion", shell})
	err := root.Execute()
	return b.String(), err
}

func TestCompletionPerShell(t *testing.T) {
	for _, sh := range []string{"bash", "zsh", "fish", "powershell"} {
		out, err := runCompletion(t, sh)
		if err != nil {
			t.Fatalf("%s: %v", sh, err)
		}
		if !strings.Contains(out, "mamori") || len(out) < 100 {
			t.Fatalf("%s: too short or missing name (%d bytes)", sh, len(out))
		}
	}
}

func TestCompletionInvalidShell(t *testing.T) {
	if _, err := runCompletion(t, "tcsh"); err == nil {
		t.Fatal("expected error for unknown shell")
	}
}

func TestManGeneratesPages(t *testing.T) {
	dir := t.TempDir()
	root := NewRootCmd("v0-test")
	var b strings.Builder
	root.SetOut(&b)
	root.SetErr(&b)
	root.SetArgs([]string{"man", "--dir", dir})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 10 {
		t.Fatalf("want >=10 man pages, got %d", len(entries))
	}
	raw, err := os.ReadFile(filepath.Join(dir, "mamori.1"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToUpper(string(raw)), "MAMORI") {
		t.Fatal("root page must mention MAMORI")
	}
}
