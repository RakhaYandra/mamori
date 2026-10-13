package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RakhaYandra/mamori/internal/audit"
)

func mkFindings() []audit.Finding {
	a := audit.NewFinding("secret.api-key", "secret", audit.SeverityHigh, "T", "a.go", 1, "****", "R")
	b := audit.NewFinding("perm.env-readable", "permissions", audit.SeverityMedium, "T", ".env", 0, "", "R")
	return []audit.Finding{a, b}
}

func TestSuppressDropsListed(t *testing.T) {
	fs := mkFindings()
	f, err := FromFindings(fs, "known")
	if err != nil {
		t.Fatal(err)
	}
	// Baseline only the first finding.
	f.Entries = f.Entries[:1]
	kept := f.Suppress(fs)
	if len(kept) != 1 || kept[0].RuleID != "perm.env-readable" {
		t.Fatalf("kept: %+v", kept)
	}
}

func TestUpdateRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".mamori-baseline")
	if err := Update(p, mkFindings(), "init"); err != nil {
		t.Fatal(err)
	}
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if kept := f.Suppress(mkFindings()); len(kept) != 0 {
		t.Fatalf("want all suppressed, kept %+v", kept)
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), "7f2a") {
		t.Fatal("baseline must not store evidence fragments")
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	f, err := Load(filepath.Join(t.TempDir(), "none"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Suppress(mkFindings())) != 2 {
		t.Fatal("missing baseline must suppress nothing")
	}
}

func TestBaselineStoresNoEvidence(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".mamori-baseline")
	fs := mkFindings()
	fs[0].Evidence = "****7f2a"
	if err := Update(p, fs, "x"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), "7f2a") {
		t.Fatal("baseline must not store evidence fragments")
	}
}
