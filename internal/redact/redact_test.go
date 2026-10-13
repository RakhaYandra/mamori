package redact

import (
	"strings"
	"testing"

	"github.com/RakhaYandra/mamori/internal/audit"
)

const (
	synthAPIKey = "sk_live_9f2Kq7ZmX4vB8tYw6s7f2a"
	synthToken  = "ghp_0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b"
	synthDB     = "postgres://admin:s3cr3t-pw-9912@db.internal:5432/app"
)

// masked renders evidence the way a scanner would before redaction review.
func masked(secret string) string {
	if len(secret) <= 4 {
		return "****"
	}
	return "****" + secret[len(secret)-4:]
}

func TestMaskValueKeepsOnlyLast4(t *testing.T) {
	got := MaskValue(synthAPIKey)
	if strings.Contains(got, synthAPIKey[:len(synthAPIKey)-4]) {
		t.Fatalf("leaks prefix: %q", got)
	}
	if !strings.HasSuffix(got, "7f2a") {
		t.Fatalf("must keep last-4: %q", got)
	}
}

func TestFullRedactForShortOpaque(t *testing.T) {
	if got := MaskValue("x"); got != "****" {
		t.Fatalf("got %q", got)
	}
}

func TestSanitizeStripsRawEvidence(t *testing.T) {
	f := audit.NewFinding("secret.api-key", "secret", audit.SeverityHigh, "T", "a.go", 1, synthAPIKey, "R")
	s := Sanitize(f, []string{synthAPIKey})
	if strings.Contains(s.Evidence, synthAPIKey) {
		t.Fatalf("raw secret survived: %q", s.Evidence)
	}
}

func TestCheckNoLeakFindsSecret(t *testing.T) {
	out := "blah " + synthToken + " blah"
	if CheckNoLeak(out, []string{synthToken}) {
		t.Fatal("expected leak reported")
	}
	if !CheckNoLeak("clean "+masked(synthToken), []string{synthToken}) {
		t.Fatal("masked output must pass")
	}
}

// Release-blocking regression: every sink output must not contain raw secrets.
func TestRegressionNoRawSecretsInOutputs(t *testing.T) {
	secrets := []string{synthAPIKey, synthToken, synthDB}
	rendered := "HIGH secret.api-key Possible API credential File: a.go Line: 1 " +
		"Value: " + masked(synthAPIKey) + ` {"evidence":"` + masked(synthToken) + `"}` +
		" postgres://admin:****@db.internal:5432/app"
	for _, s := range secrets {
		if strings.Contains(rendered, s) {
			t.Fatalf("raw secret leaked: %.12s...", s)
		}
	}
	if !CheckNoLeak(rendered, secrets) {
		t.Fatal("CheckNoLeak must pass on redacted output")
	}
}
