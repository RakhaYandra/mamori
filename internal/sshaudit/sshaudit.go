package sshaudit

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/RakhaYandra/mamori/internal/audit"
	"github.com/RakhaYandra/mamori/internal/scanner"
)

// SSHHit is one SSH client configuration finding. Scope is "global" or
// the Host block (e.g. "Host prod") the directive came from.
type SSHHit struct {
	File           string
	Scope          string
	RuleID         string
	Severity       audit.Severity
	Recommendation string
}

type directive struct {
	scope string
	key   string
	value string
}

// ParseFile reads an SSH client config with Host-block scoping.
// Directives before any Host block belong to "global".
func ParseFile(path string) ([]directive, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
		defer fh.Close()
	}
	var out []directive
	scope := "global"
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		val := strings.Join(fields[1:], " ")
		if key == "host" {
			scope = "Host " + val
			continue
		}
		out = append(out, directive{scope: scope, key: key, value: val})
	}
	if err := sc.Err(); err != nil {
		_ = fh.Close()
		return nil, err
	}
	return out, fh.Close()
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return os.ExpandEnv(p)
}

// AuditFile applies SSH client security rules to one config file.
func AuditFile(path string) ([]SSHHit, error) {
	dirs, err := ParseFile(path)
	if err != nil {
		return nil, err
	}
	var hits []SSHHit
	add := func(scope, rule string, sev audit.Severity, rec string) {
		hits = append(hits, SSHHit{File: path, Scope: scope, RuleID: rule, Severity: sev, Recommendation: rec})
	}
	wildcardRisky := map[string]bool{}
	for _, d := range dirs {
		switch d.key {
		case "stricthostkeychecking":
			if v := strings.ToLower(d.value); v == "no" || v == "off" {
				add(d.scope, "ssh.no-host-key-check", audit.SeverityHigh,
					"Re-enable host key checking unless this host is ephemeral.")
				wildcardRisky[d.scope] = wildcardRisky[d.scope] || strings.HasPrefix(d.scope, "Host *")
			}
		case "forwardagent":
			if strings.ToLower(d.value) == "yes" {
				add(d.scope, "ssh.forward-agent", audit.SeverityMedium,
					"Verify whether agent forwarding is required.")
				wildcardRisky[d.scope] = wildcardRisky[d.scope] || strings.HasPrefix(d.scope, "Host *")
			}
		case "userknownhostsfile":
			if d.value == "/dev/null" {
				add(d.scope, "ssh.known-hosts-disabled", audit.SeverityHigh,
					"Point UserKnownHostsFile at a real file.")
			}
		case "identityfile":
			for _, f := range strings.Fields(d.value) {
				ph, perr := scanner.CheckPath(expandHome(f))
				if perr != nil {
					continue
				}
				for _, h := range ph {
					add(d.scope, "ssh.identity-key-open", h.Severity,
						"Review and restrict the identity file permissions.")
				}
			}
		case "passwordauthentication":
			if strings.ToLower(d.value) == "yes" {
				add(d.scope, "ssh.password-auth", audit.SeverityMedium,
					"Prefer key authentication for SSH clients.")
			}
		}
	}
	for scope, risky := range wildcardRisky {
		if risky {
			add(scope, "ssh.wildcard-broad", audit.SeverityMedium,
				"Narrow the Host pattern for risky options.")
		}
	}
	return hits, nil
}
