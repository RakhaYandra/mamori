package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/RakhaYandra/mamori/internal/audit"
)

func chmodFile(t *testing.T, root, rel string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSSHKeyOpenFlagsHigh(t *testing.T) {
	root := t.TempDir()
	p := chmodFile(t, root, ".ssh/id_ed25519", 0o640)
	hits, err := CheckPath(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].RuleID != "perm.ssh-key-open" || hits[0].Severity != audit.SeverityHigh {
		t.Fatalf("hits: %+v", hits)
	}
}

func TestSSHKeyStrictIsClean(t *testing.T) {
	root := t.TempDir()
	p := chmodFile(t, root, ".ssh/id_ed25519", 0o600)
	hits, err := CheckPath(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("expected clean, got %+v", hits)
	}
}

func TestSSHDirAndEnv(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".ssh")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dhits, err := CheckPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(dhits) != 1 || dhits[0].RuleID != "perm.ssh-dir-open" {
		t.Fatalf("dir hits: %+v", dhits)
	}
	p := chmodFile(t, root, ".env", 0o644)
	ehits, err := CheckPath(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(ehits) != 1 || ehits[0].RuleID != "perm.env-readable" {
		t.Fatalf("env hits: %+v", ehits)
	}
}

func TestScanPermissionsCoversWalkedFiles(t *testing.T) {
	root := t.TempDir()
	p := chmodFile(t, root, "id_rsa", 0o644)
	res, err := Walk(root, WalkOptions{MaxBytes: 100})
	if err != nil {
		t.Fatal(err)
	}
	hits, perr := ScanPermissions(append(res.Files, File{Path: p}))
	if len(perr) != 0 {
		t.Fatalf("partial: %v", perr)
	}
	found := false
	for _, h := range hits {
		if h.RuleID == "perm.ssh-key-open" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected ssh-key hit in %+v", hits)
	}
}
