package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RakhaYandra/mamori/internal/rules"
)

const synthKey = "sk_live_9f2Kq7ZmX4vB8tYw6s7f2a"

func writeFile(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func scanRoot(t *testing.T, root string) []SecretHit {
	t.Helper()
	res, err := Walk(root, WalkOptions{MaxBytes: 1 << 20, ScanHidden: true})
	if err != nil {
		t.Fatal(err)
	}
	hits, partial := ScanSecrets(res.Files, 1<<20)
	if len(partial) != 0 {
		t.Fatalf("partial: %v", partial)
	}
	return hits
}

func ruleIDs(hits []SecretHit) []string {
	var out []string
	for _, h := range hits {
		out = append(out, h.RuleID)
	}
	return out
}

func TestDetectsAPIKeyMasked(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "client.go", "package c\nconst Key = \""+synthKey+"\"\n")
	hits := scanRoot(t, root)
	if len(hits) != 1 || hits[0].RuleID != "secret.api-key" {
		t.Fatalf("hits: %+v", hits)
	}
	for _, h := range hits {
		if strings.Contains(h.Masked+filepath.Base(h.File.Path), synthKey) {
			t.Fatalf("raw secret in hit: %+v", h)
		}
	}
	if !strings.HasSuffix(hits[0].Masked, "7f2a") {
		t.Fatalf("evidence must end with last-4: %q", hits[0].Masked)
	}
}

func TestLowEntropyAssignmentIgnored(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "c.go", "password = \"aaaaaaaa\"\n// password is required here\n")
	if hits := scanRoot(t, root); len(hits) != 0 {
		t.Fatalf("expected no hits, got %+v", hits)
	}
}

func TestDetectsPEMAndEnvFile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nabc\n")
	writeFile(t, root, ".env", "API_KEY="+synthKey+"\n")
	hits := scanRoot(t, root)
	ids := ruleIDs(hits)
	for _, want := range []string{"secret.pem-key", "secret.env-file", "secret.api-key"} {
		if !strings.Contains(strings.Join(ids, ","), want) {
			t.Fatalf("missing %s in %v", want, ids)
		}
	}
	for _, h := range hits {
		if strings.Contains(h.Masked, "PRIVATE KEY") && strings.Contains(h.Masked, "abc") {
			t.Fatalf("key material in evidence: %q", h.Masked)
		}
	}
}

func TestSkipsBinary(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "b.dat"), []byte{'x', 0, 'y'}, 0o644); err != nil {
		t.Fatal(err)
	}
	if hits := scanRoot(t, root); len(hits) != 0 {
		t.Fatalf("binary must be skipped: %+v", hits)
	}
}

func writeCustomRules(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "custom.yaml")
	body := "- id: custom.internal-token\n  title: T\n  severity: high\n  category: secret\n  pattern: 'INT-[A-Za-z0-9]{16}'\n  recommendation: R.\n  enabled: true\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCustomPatternFires(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.go", "token INT-abcdefgh12345678 here\n")
	res, err := Walk(root, WalkOptions{MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	custom, err := rules.LoadCustomFile(writeCustomRules(t))
	if err != nil {
		t.Fatal(err)
	}
	hits, _ := ScanSecretsWith(res.Files, 1<<20, custom)
	if len(hits) != 1 || hits[0].RuleID != "custom.internal-token" {
		t.Fatalf("hits: %+v", hits)
	}
	if !strings.HasSuffix(hits[0].Masked, "5678") {
		t.Fatalf("masked evidence: %q", hits[0].Masked)
	}
}

func TestEnvTemplateNameIgnoredButContentScanned(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".env.example", "PORT=18080\n")
	hits := scanRoot(t, root)
	if len(hits) != 0 {
		t.Fatalf("template must not fire: %+v", hits)
	}
	writeFile(t, root, "leak.env.example", "K=\""+synthKey+"\"\n")
	hits = scanRoot(t, root)
	found := false
	for _, h := range hits {
		if h.RuleID == "secret.api-key" {
			found = true
		}
		if h.RuleID == "secret.env-file" {
			t.Fatalf("template name must not fire even with secret: %+v", hits)
		}
	}
	if !found {
		t.Fatalf("real secret in template must still fire: %+v", hits)
	}
}
