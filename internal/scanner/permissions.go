package scanner

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/RakhaYandra/mamori/internal/audit"
)

// PermHit is one permission finding. Mode is the observed mode,
// Expected is the recommended tightening (advice, not enforcement).
type PermHit struct {
	Path           string
	Mode           os.FileMode
	RuleID         string
	Category       string
	Severity       audit.Severity
	Expected       string
	Recommendation string
}

func isSSHKeyName(base string) bool {
	if strings.HasSuffix(base, ".pem") {
		return true
	}
	switch base {
	case "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa":
		return true
	}
	return false
}

func isEnvName(base string) bool {
	if audit.IsEnvTemplate(base) {
		return false
	}
	return base == ".env" || strings.HasPrefix(base, ".env.")
}

// CheckPath lstats one path and reports risky permissions.
// Symlinks are evaluated themselves, never followed.
func CheckPath(p string) ([]PermHit, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, nil
	}
	var hits []PermHit
	base := filepath.Base(p)
	perm := fi.Mode().Perm()
	add := func(rule string, sev audit.Severity, expected, rec string) {
		hits = append(hits, PermHit{
			Path: p, Mode: fi.Mode(), RuleID: rule, Category: "permissions",
			Severity: sev, Expected: expected, Recommendation: rec,
		})
	}
	if fi.IsDir() {
		if base == ".ssh" && perm&0o077 != 0 {
			add("perm.ssh-dir-open", audit.SeverityMedium, "0700 or stricter",
				"Review and restrict directory permissions.")
		}
		return hits, nil
	}
	switch {
	case isSSHKeyName(base) && perm&0o077 != 0:
		add("perm.ssh-key-open", audit.SeverityHigh, "0600 or stricter",
			"Review and restrict file permissions.")
	case base == "config" && filepath.Base(filepath.Dir(p)) == ".ssh" && perm&0o022 != 0:
		add("perm.ssh-config-writable", audit.SeverityHigh, "0600 or stricter",
			"Review and restrict file permissions.")
	case isEnvName(base) && perm&0o044 != 0:
		add("perm.env-readable", audit.SeverityMedium, "0600 or stricter",
			"Review and restrict file permissions.")
	}
	return hits, nil
}

// ScanPermissions checks every walked file. Lstat errors become partial errors.
func ScanPermissions(files []File) ([]PermHit, []error) {
	var hits []PermHit
	var partial []error
	for _, f := range files {
		h, err := CheckPath(f.Path)
		if err != nil {
			partial = append(partial, err)
			continue
		}
		hits = append(hits, h...)
	}
	return hits, partial
}
