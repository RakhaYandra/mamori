package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const customYAML = `
- id: custom.internal-token
  title: Internal token format
  severity: high
  category: secret
  pattern: 'INT-[A-Za-z0-9]{16}'
  recommendation: Rotate it.
  enabled: true
`

func writeCustom(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "custom.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadCustomPatternCompiles(t *testing.T) {
	rs, err := LoadCustomFile(writeCustom(t, customYAML))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || rs[0].ID != "custom.internal-token" {
		t.Fatalf("got %+v", rs)
	}
	if rs[0].Compiled == nil || !rs[0].Compiled.MatchString("INT-abcdefgh12345678") {
		t.Fatalf("pattern must match: %+v", rs[0])
	}
}

func TestCustomRejectsMissingPrefix(t *testing.T) {
	body := "- id: secret.evil\n  title: T\n  severity: high\n  category: secret\n  pattern: 'X+'\n  recommendation: R.\n  enabled: true\n"
	if _, err := LoadCustomFile(writeCustom(t, body)); err == nil {
		t.Fatal("expected error for non-custom. id")
	}
}

func TestCustomRejectsBadRegex(t *testing.T) {
	body := "- id: custom.bad\n  title: T\n  severity: high\n  category: secret\n  pattern: '([unclosed'\n  recommendation: R.\n  enabled: true\n"
	if _, err := LoadCustomFile(writeCustom(t, body)); err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestCustomRejectsOversizePattern(t *testing.T) {
	long := strings.Repeat("A", 5000)
	body := "- id: custom.big\n  title: T\n  severity: high\n  category: secret\n  pattern: '" + long + "'\n  recommendation: R.\n  enabled: true\n"
	if _, err := LoadCustomFile(writeCustom(t, body)); err == nil {
		t.Fatal("expected error for oversize pattern")
	}
}
