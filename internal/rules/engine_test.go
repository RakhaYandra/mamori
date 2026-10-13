package rules

import (
	"os"
	"path/filepath"
	"testing"
)

const validYAML = `
- id: secret.api-key
  title: Possible API credential
  severity: high
  category: secret
  recommendation: Move it.
  enabled: true
- id: secret.old
  title: Old
  severity: low
  category: secret
  recommendation: R.
  enabled: false
`

func writeRules(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "r.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValidFiltersEnabled(t *testing.T) {
	rs, err := LoadFile(writeRules(t, validYAML))
	if err != nil {
		t.Fatal(err)
	}
	got := Enabled(rs)
	if len(got) != 1 || got[0].ID != "secret.api-key" {
		t.Fatalf("got %+v", got)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	if _, err := LoadFile(writeRules(t, "- id: x\n  title: T\n  nope: 1\n")); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadRejectsBadSeverity(t *testing.T) {
	body := "- id: x\n  title: T\n  severity: extreme\n  category: c\n  recommendation: r\n  enabled: true\n"
	if _, err := LoadFile(writeRules(t, body)); err == nil {
		t.Fatal("expected error")
	}
}

func TestBundledRulesLoad(t *testing.T) {
	rs, err := LoadDir("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(Enabled(rs)) < 17 {
		t.Fatalf("want >=8 bundled rules, got %d", len(Enabled(rs)))
	}
}
