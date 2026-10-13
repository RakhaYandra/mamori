package sshaudit

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func ruleIDs(hits []SSHHit) []string {
	var out []string
	for _, h := range hits {
		out = append(out, h.RuleID)
	}
	return out
}

func TestDetectsRiskyDirectives(t *testing.T) {
	p := writeCfg(t, "Host prod\n  HostName example.com\n  ForwardAgent yes\n  StrictHostKeyChecking no\n")
	hits, err := AuditFile(p)
	if err != nil {
		t.Fatal(err)
	}
	ids := ruleIDs(hits)
	for _, want := range []string{"ssh.forward-agent", "ssh.no-host-key-check"} {
		found := false
		for _, id := range ids {
			if id == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing %s in %v", want, ids)
		}
	}
	for _, h := range hits {
		if h.Scope != "Host prod" {
			t.Fatalf("scope must be Host prod: %+v", h)
		}
	}
}

func TestGlobalBlockSeparateFromHost(t *testing.T) {
	p := writeCfg(t, "StrictHostKeyChecking no\nHost prod\n  HostName example.com\n")
	hits, err := AuditFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Scope != "global" {
		t.Fatalf("global directive must scope global: %+v", hits)
	}
}

func TestWildcardWithRiskFlags(t *testing.T) {
	p := writeCfg(t, "Host *\n  ForwardAgent yes\n")
	hits, err := AuditFile(p)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range hits {
		if h.RuleID == "ssh.wildcard-broad" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing wildcard-broad in %+v", ruleIDs(hits))
	}
}

func TestCleanConfig(t *testing.T) {
	p := writeCfg(t, "Host prod\n  HostName example.com\n  IdentityFile ~/.ssh/id_ed25519\n")
	hits, err := AuditFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// IdentityFile points at missing test-home file: skipped silently.
	for _, h := range hits {
		if h.RuleID == "ssh.forward-agent" || h.RuleID == "ssh.no-host-key-check" {
			t.Fatalf("false positive: %+v", hits)
		}
	}
}

func TestMissingFileErrors(t *testing.T) {
	if _, err := AuditFile(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Fatal("expected error")
	}
}
