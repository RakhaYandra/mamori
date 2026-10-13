package scanner

import (
	"bufio"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/RakhaYandra/mamori/internal/audit"
	"github.com/RakhaYandra/mamori/internal/redact"
)

// SecretHit is one redacted secret detection. Masked never holds raw values.
type SecretHit struct {
	File           File
	Line           int
	RuleID         string
	Category       string
	Severity       audit.Severity
	Masked         string
	Recommendation string
}

type secretPattern struct {
	ruleID string
	sev    audit.Severity
	re     *regexp.Regexp
	mask   bool // mask last-4 of group 2; false = full redact
	rec    string
}

var secretPatterns = []secretPattern{
	{
		ruleID: "secret.api-key", sev: audit.SeverityHigh,
		re:   regexp.MustCompile(`\b(sk_live_[A-Za-z0-9]+|sk_test_[A-Za-z0-9]+|xox[bap]-[A-Za-z0-9-]+|AIza[A-Za-z0-9_-]{10,}|ghp_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}|AKIA[0-9A-Z]{16})\b`),
		mask: true, rec: "Move the credential to a secure secret store and rotate it.",
	},
	{
		ruleID: "secret.db-conn", sev: audit.SeverityHigh,
		re:   regexp.MustCompile(`(?i)\b(postgres(ql)?|mysql|mongodb(\+srv)?)://[^\s'"]+`),
		mask: false, rec: "Move the connection string out of source and rotate credentials.",
	},
	{
		ruleID: "secret.pem-key", sev: audit.SeverityHigh,
		re:   regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`),
		mask: false, rec: "Keep private keys out of repositories; restrict file permissions.",
	},
	{
		ruleID: "secret.generic-assignment", sev: audit.SeverityMedium,
		re:   regexp.MustCompile(`(?i)\b(api[_-]?key|password|passwd|secret|token)\s*[:=]\s*['"]?([A-Za-z0-9_.\-/+]{8,})['"]?`),
		mask: true, rec: "Move the value to a secure secret store and rotate it.",
	},
}

var placeholders = []string{"test", "example", "changeme", "xxx", "dummy", "placeholder", "your_", "***", "<", "todo"}

// shannon entropy bits per character.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	var e float64
	n := float64(len([]rune(s)))
	for _, c := range freq {
		p := c / n
		e -= p * math.Log2(p)
	}
	return e
}

func isPlaceholder(v string) bool {
	lower := strings.ToLower(v)
	for _, p := range placeholders {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// ScanSecrets scans files line by line, bounded by maxBytes per file.
// Raw values never leave this function; hits carry masked evidence only.
func ScanSecrets(files []File, maxBytes int64) ([]SecretHit, []error) {
	var hits []SecretHit
	var partial []error
	for _, f := range files {
		if f.Binary {
			continue
		}
		if isEnvFile(f.Path) {
			hits = append(hits, SecretHit{
				File: f, RuleID: "secret.env-file", Category: "secret",
				Severity: audit.SeverityMedium, Masked: "environment file (name only)",
				Recommendation: "Do not commit environment files; check Git tracking with `mamori git`.",
			})
		}
		fh, err := os.Open(f.Path)
		if err != nil {
			partial = append(partial, err)
			continue
		}
		var read int64
		line := 0
		r := bufio.NewReader(fh)
		for {
			s, err := r.ReadString('\n')
			line++
			read += int64(len(s))
			checkLine(f, line, s, &hits)
			if maxBytes > 0 && read >= maxBytes {
				break
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				partial = append(partial, err)
				break
			}
		}
		_ = fh.Close()
	}
	return hits, partial
}

func isEnvFile(p string) bool {
	base := filepath.Base(p)
	return base == ".env" || strings.HasPrefix(base, ".env.")
}

// CheckSecretLine matches one line against secret patterns.
// It returns the rule metadata with masked evidence, never raw values.
// ok is false for non-matches, placeholders, and low-entropy values.
func CheckSecretLine(s string) (ruleID string, sev audit.Severity, masked, rec string, ok bool) {
	for _, p := range secretPatterns {
		m := p.re.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		token := m[0]
		if len(m) > 2 && m[2] != "" {
			token = m[2]
		}
		if isPlaceholder(token) || entropy(token) < 3.0 {
			continue
		}
		masked := "credential value (redacted)"
		if p.mask {
			masked = redact.MaskValue(token)
		}
		return p.ruleID, p.sev, masked, p.rec, true
	}
	return "", "", "", "", false
}

func checkLine(f File, line int, s string, hits *[]SecretHit) {
	ruleID, sev, masked, rec, ok := CheckSecretLine(s)
	if !ok {
		return
	}
	*hits = append(*hits, SecretHit{
		File: f, Line: line, RuleID: ruleID, Category: "secret",
		Severity: sev, Masked: masked, Recommendation: rec,
	})
}
