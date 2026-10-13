package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewFindingHasUniqueIDs(t *testing.T) {
	a := NewFinding("secret.api-key", "secret", SeverityHigh, "Possible API credential", "a.go", 1, "masked", "Move it.")
	b := NewFinding("secret.api-key", "secret", SeverityHigh, "Possible API credential", "a.go", 1, "masked", "Move it.")
	if a.ID == "" || b.ID == "" {
		t.Fatal("ID must not be empty")
	}
	if a.ID == b.ID {
		t.Fatal("IDs must be unique per finding")
	}
}

func TestSeverityParses(t *testing.T) {
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if _, err := ParseSeverity(s); err != nil {
			t.Fatalf("ParseSeverity(%q): %v", s, err)
		}
	}
	if _, err := ParseSeverity("bogus"); err == nil {
		t.Fatal("expected error for bogus severity")
	}
}

func TestFindingJSONKeysStable(t *testing.T) {
	f := NewFinding("perm.ssh-key", "permissions", SeverityMedium, "T", "k", 0, "e", "r")
	raw, _ := json.Marshal(f)
	for _, k := range []string{`"id"`, `"rule_id"`, `"category"`, `"severity"`, `"title"`, `"recommendation"`} {
		if !strings.Contains(string(raw), k) {
			t.Fatalf("missing key %s in %s", k, raw)
		}
	}
	if strings.Contains(string(raw), "raw") {
		t.Fatalf("must not contain raw-content keys: %s", raw)
	}
}
