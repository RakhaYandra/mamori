package report

import (
	"strings"
	"testing"

	"github.com/RakhaYandra/mamori/internal/audit"
	"github.com/RakhaYandra/mamori/internal/redact"
)

const rawKey = "sk_live_9f2Kq7ZmX4vB8tYw6s7f2a"

func sample() []audit.Finding {
	return []audit.Finding{
		audit.NewFinding("secret.api-key", "secret", audit.SeverityHigh, "Possible API credential", "a.go", 1, redact.MaskValue(rawKey), "Move it."),
		audit.NewFinding("perm.env-readable", "permissions", audit.SeverityMedium, "Env readable", ".env", 0, "", "Restrict it."),
	}
}

func TestTerminalShowsCounts(t *testing.T) {
	var b strings.Builder
	if err := RenderTerminal(&b, "/t", sample(), false); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"/t", "secret.api-key", "HIGH", "1", "Overall: 2 findings"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if !redact.CheckNoLeak(out, []string{rawKey}) {
		t.Fatal("raw secret in terminal output")
	}
}

func TestTerminalQuietOmitsDetails(t *testing.T) {
	var b strings.Builder
	if err := RenderTerminal(&b, "/t", sample(), true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "secret.api-key") {
		t.Fatal("quiet must omit finding details")
	}
}

func TestJSONShapeAndNoLeak(t *testing.T) {
	var b strings.Builder
	if err := RenderJSON(&b, "/t", sample()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{`"schema_version":"v1"`, `"rule_id":"secret.api-key"`, `"severity":"high"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if !redact.CheckNoLeak(out, []string{rawKey}) {
		t.Fatal("raw secret in JSON output")
	}
}
