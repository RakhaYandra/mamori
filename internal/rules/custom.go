package rules

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/RakhaYandra/mamori/internal/audit"
	"gopkg.in/yaml.v3"
)

// MaxCustomPattern caps user regex length.
const MaxCustomPattern = 4096

// CustomRule is a user-supplied secret pattern. The ID must start with
// "custom." so user rules can never shadow bundled rule IDs.
type CustomRule struct {
	ID             string `yaml:"id"`
	Title          string `yaml:"title"`
	Severity       string `yaml:"severity"`
	Category       string `yaml:"category"`
	Pattern        string `yaml:"pattern"`
	Recommendation string `yaml:"recommendation"`
	Enabled        bool   `yaml:"enabled"`

	Compiled *regexp.Regexp `yaml:"-"`
}

// Validate enforces schema plus safety bounds. Go regexp is RE2: no
// backtracking attacks, but patterns are still length-capped.
func (r *CustomRule) Validate() error {
	if !strings.HasPrefix(r.ID, "custom.") {
		return fmt.Errorf("custom rule id %q must start with \"custom.\"", r.ID)
	}
	if r.Title == "" || r.Category == "" || r.Recommendation == "" {
		return fmt.Errorf("custom rule %q: title/category/recommendation required", r.ID)
	}
	if _, err := audit.ParseSeverity(r.Severity); err != nil {
		return fmt.Errorf("custom rule %q: %w", r.ID, err)
	}
	if r.Pattern == "" {
		return fmt.Errorf("custom rule %q: pattern required", r.ID)
	}
	if len(r.Pattern) > MaxCustomPattern {
		return fmt.Errorf("custom rule %q: pattern exceeds %d bytes", r.ID, MaxCustomPattern)
	}
	re, err := regexp.Compile(r.Pattern)
	if err != nil {
		return fmt.Errorf("custom rule %q: bad pattern: %v", r.ID, err)
	}
	r.Compiled = re
	return nil
}

// LoadCustomFile parses one user rule file with strict fields.
func LoadCustomFile(path string) ([]CustomRule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read custom rules: %w", err)
	}
	var rs []CustomRule
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&rs); err != nil {
		return nil, fmt.Errorf("parse custom rules: %w", err)
	}
	for i := range rs {
		if err := rs[i].Validate(); err != nil {
			return nil, err
		}
	}
	return rs, nil
}

// LoadCustomDir loads every *.yaml/*.yml file in dir.
// A missing dir means no custom rules, not an error.
func LoadCustomDir(dir string) ([]CustomRule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read custom rules dir: %w", err)
	}
	var all []CustomRule
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		rs, err := LoadCustomFile(dir + "/" + e.Name())
		if err != nil {
			return nil, err
		}
		all = append(all, rs...)
	}
	return all, nil
}
