// Package baseline suppresses already-known findings.
// Entries key on Finding.Fingerprint (a stable rule+path hash), never on
// the random Finding.ID, and never store evidence or secret fragments.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/RakhaYandra/mamori/internal/audit"
)

// Version versions the baseline file format.
const Version = 1

// Entry is one acknowledged finding.
type Entry struct {
	Fingerprint string `json:"fingerprint"`
	Rule        string `json:"rule"`
	Path        string `json:"path"`
	Note        string `json:"note,omitempty"`
}

// File is the parsed .mamori-baseline document.
type File struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// Load reads a baseline file. A missing file yields an empty baseline.
func Load(path string) (File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return File{Version: Version}, nil
		}
		return File{}, fmt.Errorf("read baseline: %w", err)
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return File{}, fmt.Errorf("parse baseline: %w", err)
	}
	if f.Version != Version {
		return File{}, fmt.Errorf("unsupported baseline version %d", f.Version)
	}
	return f, nil
}

// FromFindings builds a baseline acknowledging every finding.
func FromFindings(fs []audit.Finding, note string) (File, error) {
	f := File{Version: Version}
	for _, finding := range fs {
		if finding.Fingerprint == "" {
			return File{}, fmt.Errorf("finding %s has no fingerprint", finding.RuleID)
		}
		f.Entries = append(f.Entries, Entry{
			Fingerprint: finding.Fingerprint,
			Rule:        finding.RuleID,
			Path:        finding.Path,
			Note:        note,
		})
	}
	return f, nil
}

// save writes the baseline with owner-only permissions.
func (f File) save(path string) error {
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

// Update acknowledges the current findings, replacing the file.
func Update(path string, fs []audit.Finding, note string) error {
	f, err := FromFindings(fs, note)
	if err != nil {
		return err
	}
	return f.save(path)
}

// Suppress drops findings whose fingerprint is baselined.
func (f File) Suppress(fs []audit.Finding) []audit.Finding {
	known := map[string]bool{}
	for _, e := range f.Entries {
		known[e.Fingerprint] = true
	}
	var kept []audit.Finding
	for _, finding := range fs {
		if !known[finding.Fingerprint] {
			kept = append(kept, finding)
		}
	}
	return kept
}
