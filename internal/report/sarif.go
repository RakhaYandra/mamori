package report

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	"github.com/RakhaYandra/mamori/internal/audit"
	"github.com/RakhaYandra/mamori/internal/redact"
)

// sarifLevel maps severities to SARIF levels.
func sarifLevel(s audit.Severity) string {
	switch s {
	case audit.SeverityCritical, audit.SeverityHigh:
		return "error"
	case audit.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

type sarifRule struct {
	ID               string `json:"id"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	Help struct {
		Text string `json:"text"`
	} `json:"help"`
}

type sarifResult struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region *struct {
				StartLine int `json:"startLine"`
			} `json:"region,omitempty"`
		} `json:"physicalLocation"`
	} `json:"locations,omitempty"`
}

type sarifDoc struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name    string      `json:"name"`
				Version string      `json:"version"`
				Rules   []sarifRule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	} `json:"runs"`
}

// RenderSARIF writes SARIF 2.1.0 for CI code scanning. Messages carry the
// title and recommendation only — never evidence — so shared SARIF stays
// free of credential fragments. Paths under target become relative.
func RenderSARIF(w io.Writer, target string, fs []audit.Finding, toolVersion string) error {
	fs = redact.SanitizeAll(fs, nil)
	doc := sarifDoc{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json"}
	var run struct {
		Tool struct {
			Driver struct {
				Name    string      `json:"name"`
				Version string      `json:"version"`
				Rules   []sarifRule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	run.Tool.Driver.Name = "mamori"
	run.Tool.Driver.Version = toolVersion
	seen := map[string]bool{}
	for _, f := range fs {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			var r sarifRule
			r.ID = f.RuleID
			r.ShortDescription.Text = f.Title
			r.Help.Text = f.Recommendation
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, r)
		}
		var res sarifResult
		res.RuleID = f.RuleID
		res.Level = sarifLevel(f.Severity)
		res.Message.Text = f.Title + ". " + f.Recommendation
		if f.Path != "" {
			uri := f.Path
			if rel, err := filepath.Rel(target, f.Path); err == nil && !strings.HasPrefix(rel, "..") {
				uri = rel
			}
			var loc struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region *struct {
						StartLine int `json:"startLine"`
					} `json:"region,omitempty"`
				} `json:"physicalLocation"`
			}
			loc.PhysicalLocation.ArtifactLocation.URI = uri
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &struct {
					StartLine int `json:"startLine"`
				}{StartLine: f.Line}
			}
			res.Locations = append(res.Locations, loc)
		}
		run.Results = append(run.Results, res)
	}
	doc.Runs = append(doc.Runs, run)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}
