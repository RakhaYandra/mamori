package auditor_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RakhaYandra/mamori/internal/audit"
	"github.com/RakhaYandra/mamori/internal/auditor"
	"github.com/RakhaYandra/mamori/internal/redact"
)

const e2eKey = "sk_live_9f2Kq7ZmX4vB8tYw6s7f2a"

var e2eTitles = map[string]string{
	"secret.api-key":    "Possible API credential",
	"secret.env-file":   "Environment file present",
	"perm.ssh-key-open": "SSH private key is accessible",
}

func mkE2E(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.go"), []byte("const K = \""+e2eKey+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	kp := filepath.Join(root, "id_ed25519")
	if err := os.WriteFile(kp, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(kp, 0o640); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestRunFindsSecretsAndPerms(t *testing.T) {
	res, err := auditor.Run(auditor.Options{Target: mkE2E(t), Titles: e2eTitles, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) < 2 {
		t.Fatalf("want >=2 findings, got %+v", res.Findings)
	}
	seen := map[string]bool{}
	for _, f := range res.Findings {
		seen[f.RuleID] = true
		if strings.Contains(f.Evidence+f.Title, e2eKey) {
			t.Fatalf("raw secret in finding: %+v", f)
		}
	}
	if !seen["secret.api-key"] || !seen["perm.ssh-key-open"] {
		t.Fatalf("missing rules in %v", seen)
	}
}

func TestRunRespectsMinSeverity(t *testing.T) {
	res, err := auditor.Run(auditor.Options{Target: mkE2E(t), Titles: e2eTitles, MaxBytes: 1 << 20, MinSeverity: audit.SeverityCritical})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("critical filter must hide high/medium: %+v", res.Findings)
	}
}

func TestExitCodes(t *testing.T) {
	if got := auditor.ExitCode(auditor.Result{}); got != 0 {
		t.Fatalf("clean = 0, got %d", got)
	}
	if got := auditor.ExitCode(auditor.Result{Findings: []audit.Finding{{}}}); got != 1 {
		t.Fatalf("findings = 1, got %d", got)
	}
	if got := auditor.ExitCode(auditor.Result{Partial: []error{os.ErrClosed}}); got != 3 {
		t.Fatalf("partial = 3, got %d", got)
	}
	// Findings outrank partial: risks found is the signal.
	if got := auditor.ExitCode(auditor.Result{Findings: []audit.Finding{{}}, Partial: []error{os.ErrClosed}}); got != 1 {
		t.Fatalf("findings+partial = 1, got %d", got)
	}
}

func TestRenderedE2EHasNoLeak(t *testing.T) {
	res, err := auditor.Run(auditor.Options{Target: mkE2E(t), Titles: e2eTitles, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, f := range res.Findings {
		b.WriteString(f.Evidence + f.Recommendation + f.Title)
	}
	if !redact.CheckNoLeak(b.String(), []string{e2eKey}) {
		t.Fatal("raw secret leaked through pipeline")
	}
}
