// Package rules loads data-only audit rules. Rules carry metadata;
// detection lives in the scanners. No expressions, no shell, no code.
package rules

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/RakhaYandra/mamori/internal/audit"
	"gopkg.in/yaml.v3"
)

// Rule is one auditable check.
type Rule struct {
	ID             string `yaml:"id"`
	Title          string `yaml:"title"`
	Severity       string `yaml:"severity"`
	Category       string `yaml:"category"`
	Recommendation string `yaml:"recommendation"`
	Enabled        bool   `yaml:"enabled"`
}

// Validate enforces the schema.
func (r Rule) Validate() error {
	if r.ID == "" || r.Title == "" || r.Category == "" || r.Recommendation == "" {
		return fmt.Errorf("rule %+v: id/title/category/recommendation required", r.ID)
	}
	if _, err := audit.ParseSeverity(r.Severity); err != nil {
		return fmt.Errorf("rule %q: %w", r.ID, err)
	}
	return nil
}

// LoadFile parses one YAML rule file with strict fields.
func LoadFile(path string) ([]Rule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	var rs []Rule
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&rs); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	for _, r := range rs {
		if err := r.Validate(); err != nil {
			return nil, err
		}
	}
	return rs, nil
}

// LoadDir loads every *.yaml/*.yml file in dir.
func LoadDir(dir string) ([]Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir: %w", err)
	}
	var all []Rule
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		rs, err := LoadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		all = append(all, rs...)
	}
	return all, nil
}

// Enabled returns only enabled rules.
func Enabled(rs []Rule) []Rule {
	var out []Rule
	for _, r := range rs {
		if r.Enabled {
			out = append(out, r)
		}
	}
	return out
}

// ByID finds a rule by ID.
func ByID(rs []Rule, id string) (Rule, bool) {
	for _, r := range rs {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}
