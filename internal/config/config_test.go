package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
}

func TestLoadMissingReturnsDefault(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Version != 1 || !cfg.Report.RedactSecrets {
		t.Fatalf("unexpected default: %+v", cfg)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	body := "version: 1\nscan:\n  max_file_size: 5MB\nreport:\n  redact_secrets: true\nnonsense: true\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestValidateRejectsRedactionOff(t *testing.T) {
	cfg := Default()
	cfg.Report.RedactSecrets = false
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when redact_secrets is false")
	}
}
