// Package config loads and validates ~/.config/mamori/config.yaml.
package config

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the validated user configuration.
type Config struct {
	Version uint          `yaml:"version"`
	Scan    ScanConfig    `yaml:"scan"`
	Exclude ExcludeConfig `yaml:"exclude"`
	Report  ReportConfig  `yaml:"report"`
}

// ScanConfig controls traversal limits.
type ScanConfig struct {
	MaxFileSize    string `yaml:"max_file_size"`
	FollowSymlinks bool   `yaml:"follow_symlinks"`
	ScanHidden     bool   `yaml:"scan_hidden_files"`
	ScanGitHistory bool   `yaml:"scan_git_history"`
}

// ExcludeConfig lists skipped paths and rules.
type ExcludeConfig struct {
	Paths []string `yaml:"paths"`
	Rules []string `yaml:"rules"`
}

// ReportConfig controls output safety.
type ReportConfig struct {
	Format          string `yaml:"format"`
	RedactSecrets   bool   `yaml:"redact_secrets"`
	ShowLineNumbers bool   `yaml:"show_line_numbers"`
}

// Default returns the default configuration.
func Default() Config {
	return Config{
		Version: 1,
		Scan: ScanConfig{
			MaxFileSize:    "5MB",
			FollowSymlinks: false,
			ScanHidden:     true,
			ScanGitHistory: false,
		},
		Exclude: ExcludeConfig{
			Paths: []string{"**/node_modules/**", "**/vendor/**", "**/.cache/**"},
		},
		Report: ReportConfig{
			Format:          "terminal",
			RedactSecrets:   true,
			ShowLineNumbers: true,
		},
	}
}

// Load reads path (or the default location when empty) and validates it.
func Load(path string) (Config, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Config{}, fmt.Errorf("resolve home dir: %w", err)
		}
		path = home + "/.config/mamori/config.yaml"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Default(), nil
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate enforces the schema: version 1, known formats, redaction on.
func (c Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported config version %d: want 1", c.Version)
	}
	switch c.Report.Format {
	case "", "terminal", "json":
	default:
		return fmt.Errorf("unsupported report.format %q: want terminal|json", c.Report.Format)
	}
	if !c.Report.RedactSecrets {
		return fmt.Errorf("report.redact_secrets must stay true")
	}
	if c.Scan.MaxFileSize == "" {
		return fmt.Errorf("scan.max_file_size must not be empty")
	}
	return nil
}
