// Package audit defines the safe finding model shared by all scanners.
package audit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Severity of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// ParseSeverity validates a severity name.
func ParseSeverity(s string) (Severity, error) {
	switch Severity(s) {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return Severity(s), nil
	}
	return "", fmt.Errorf("unknown severity %q", s)
}

// AtLeast reports whether s meets the minimum threshold min.
func (s Severity) AtLeast(min Severity) bool {
	rank := map[Severity]int{
		SeverityInfo: 0, SeverityLow: 1, SeverityMedium: 2, SeverityHigh: 3, SeverityCritical: 4,
	}
	return rank[s] >= rank[min]
}

// Finding is one redacted audit result. It never carries raw secret content.
type Finding struct {
	ID             string   `json:"id"`
	RuleID         string   `json:"rule_id"`
	Category       string   `json:"category"`
	Severity       Severity `json:"severity"`
	Title          string   `json:"title"`
	Path           string   `json:"path,omitempty"`
	Line           int      `json:"line,omitempty"`
	Evidence       string   `json:"evidence,omitempty"`
	Recommendation string   `json:"recommendation"`
	Fingerprint    string   `json:"fingerprint,omitempty"`
}

// IsEnvTemplate reports whether a basename is an environment template
// (e.g. .env.example). Templates are committed intentionally and carry no
// real credentials by convention; name-based rules skip them while content
// scanning still applies.
func IsEnvTemplate(base string) bool {
	for _, suf := range []string{".example", ".sample", ".dist", ".template"} {
		if strings.HasSuffix(base, suf) {
			return true
		}
	}
	return false
}

// NewFinding builds a Finding with a random ID. evidence must already be
// redacted; pass "" when there is nothing safe to show.
func NewFinding(ruleID, category string, sev Severity, title, path string, line int, evidence, recommendation string) Finding {
	var id [16]byte
	_, _ = rand.Read(id[:])
	sum := sha256.Sum256([]byte(ruleID + "\x00" + path))
	return Finding{
		ID:             hex.EncodeToString(id[:]),
		RuleID:         ruleID,
		Category:       category,
		Severity:       sev,
		Title:          title,
		Path:           path,
		Line:           line,
		Evidence:       evidence,
		Recommendation: recommendation,
		Fingerprint:    hex.EncodeToString(sum[:16]),
	}
}
