// Package redact is the single path from findings to any output sink.
// Every renderer must pass findings through Sanitize first.
package redact

import (
	"strings"

	"github.com/RakhaYandra/mamori/internal/audit"
)

// MaskValue shows only the last 4 characters of a patterned credential.
// Short or opaque values collapse to "****" with no fragment.
func MaskValue(secret string) string {
	if len(secret) <= 4 {
		return "****"
	}
	return "****" + secret[len(secret)-4:]
}

// Sanitize replaces any occurrence of known raw secrets in Evidence with
// their masked form. Findings must already avoid raw content; this is the
// backstop, not the primary control.
func Sanitize(f audit.Finding, knownSecrets []string) audit.Finding {
	out := f
	for _, s := range knownSecrets {
		if s == "" {
			continue
		}
		out.Evidence = strings.ReplaceAll(out.Evidence, s, MaskValue(s))
	}
	return out
}

// SanitizeAll sanitizes every finding.
func SanitizeAll(fs []audit.Finding, knownSecrets []string) []audit.Finding {
	out := make([]audit.Finding, len(fs))
	for i, f := range fs {
		out[i] = Sanitize(f, knownSecrets)
	}
	return out
}

// CheckNoLeak reports true when output contains none of the raw secrets.
func CheckNoLeak(output string, rawSecrets []string) bool {
	for _, s := range rawSecrets {
		if s != "" && strings.Contains(output, s) {
			return false
		}
	}
	return true
}
