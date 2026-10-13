package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/RakhaYandra/mamori/internal/audit"
	"github.com/RakhaYandra/mamori/internal/redact"
)

func TestSARIFShape(t *testing.T) {
	var b strings.Builder
	if err := RenderSARIF(&b, "/t", sample(), "v0.1.0"); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(b.String()), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["version"] != "2.1.0" {
		t.Fatalf("version: %v", doc["version"])
	}
	runs := doc["runs"].([]any)
	tool := runs[0].(map[string]any)["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	if driver["name"] != "mamori" || driver["version"] != "v0.1.0" {
		t.Fatalf("driver: %v", driver)
	}
	if !redact.CheckNoLeak(b.String(), []string{rawKey}) {
		t.Fatal("raw secret in SARIF output")
	}
}

func TestSARIFLevels(t *testing.T) {
	fs := []audit.Finding{
		audit.NewFinding("a", "secret", audit.SeverityCritical, "T", "a", 1, "", "R"),
		audit.NewFinding("b", "secret", audit.SeverityMedium, "T", "b", 1, "", "R"),
		audit.NewFinding("c", "secret", audit.SeverityInfo, "T", "c", 1, "", "R"),
	}
	var b strings.Builder
	if err := RenderSARIF(&b, "/t", fs, "v0"); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal([]byte(b.String()), &doc)
	var levels []string
	for _, r := range doc["runs"].([]any)[0].(map[string]any)["results"].([]any) {
		levels = append(levels, r.(map[string]any)["level"].(string))
	}
	got := strings.Join(levels, ",")
	if got != "error,warning,note" {
		t.Fatalf("levels: %s", got)
	}
}

func TestSARIFRelativizesPaths(t *testing.T) {
	fs := []audit.Finding{
		audit.NewFinding("a", "secret", audit.SeverityHigh, "T", "/t/sub/a.go", 3, "", "R"),
		audit.NewFinding("b", "secret", audit.SeverityHigh, "T", "/elsewhere/b.go", 0, "", "R"),
	}
	var b strings.Builder
	if err := RenderSARIF(&b, "/t", fs, "v0"); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, `"uri":"sub/a.go"`) {
		t.Fatalf("path under target must relativize:\n%s", out)
	}
	if !strings.Contains(out, `"uri":"/elsewhere/b.go"`) {
		t.Fatalf("outside path must stay absolute:\n%s", out)
	}
	if !strings.Contains(out, `"startLine":3`) {
		t.Fatalf("line must map to region:\n%s", out)
	}
}
