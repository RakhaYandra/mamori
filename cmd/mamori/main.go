// Command mamori is a local-first Linux security auditor for developer machines.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/RakhaYandra/mamori/internal/audit"
	"github.com/RakhaYandra/mamori/internal/auditor"
	"github.com/RakhaYandra/mamori/internal/config"
	"github.com/RakhaYandra/mamori/internal/gitinspect"
	"github.com/RakhaYandra/mamori/internal/report"
	"github.com/RakhaYandra/mamori/internal/rules"
	"github.com/RakhaYandra/mamori/internal/scanner"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"strings"
)

var version = "v0.1.0-dev"

var (
	cfgPath  string
	severity string
	format   string
	excludes []string
	noColor  bool
	quiet    bool
	verbose  bool
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(2)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "mamori",
		Short: "Local security auditor for Linux developer machines",
		Long: `Mamori audits local security hygiene: secrets, Git exposure,
file permissions, and SSH configuration. Read-only, local-first,
no network, no raw secrets in output.`,
		SilenceUsage: true,
	}

	root.PersistentFlags().StringVar(&cfgPath, "config", "", "config file path")
	root.PersistentFlags().StringVar(&severity, "severity", "", "minimum severity (critical|high|medium|low|info)")
	root.PersistentFlags().StringVar(&format, "format", "terminal", "output format (terminal|json)")
	root.PersistentFlags().StringSliceVar(&excludes, "exclude", nil, "additional exclusion patterns")
	root.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colors")
	root.PersistentFlags().BoolVar(&quiet, "quiet", false, "summary only")
	root.PersistentFlags().BoolVar(&verbose, "verbose", false, "safe diagnostic details")

	root.AddCommand(
		auditCmd(),
		secretsCmd(),
		permissionsCmd(),
		sshCmd(),
		gitCmd(),
		reportCmd(),
		rulesCmd(),
		configCmd(),
		versionCmd(),
	)

	return root
}

// rulesPath locates bundled rules: beside the repo (dev), cwd, or user config.
func rulesPath() string {
	if exe, err := os.Executable(); err == nil {
		if d, err := rules.LoadDir(filepath.Join(filepath.Dir(exe), "..", "rules")); err == nil && len(d) > 0 {
			return filepath.Join(filepath.Dir(exe), "..", "rules")
		}
	}
	if _, err := os.Stat("rules"); err == nil {
		return "rules"
	}
	if home, err := os.UserHomeDir(); err == nil {
		if _, err := os.Stat(filepath.Join(home, ".config", "mamori", "rules")); err == nil {
			return filepath.Join(home, ".config", "mamori", "rules")
		}
	}
	return "rules"
}

func loadTitles() map[string]string {
	titles := map[string]string{}
	rs, err := rules.LoadDir(rulesPath())
	if err != nil {
		return titles
	}
	for _, r := range rs {
		titles[r.ID] = r.Title
	}
	return titles
}

type categoryFilter string

const (
	catAll         categoryFilter = ""
	catSecret      categoryFilter = "secret"
	catPermissions categoryFilter = "permissions"
	catGit         categoryFilter = "git"
	catSSH         categoryFilter = "ssh"
)

var (
	histFlag    bool
	histLimit   int
	stagedFlag  bool
	trackedFlag bool
	sshCfgFlag  string
)

func runAudit(cmd *cobra.Command, target string, only categoryFilter) int {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "config: %v\n", err)
		return 2
	}
	maxBytes, err := scanner.ParseSize(cfg.Scan.MaxFileSize)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "config: %v\n", err)
		return 2
	}
	var min audit.Severity
	if severity != "" {
		min, err = audit.ParseSeverity(severity)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "severity: %v\n", err)
			return 2
		}
	}
	if format != "terminal" && format != "json" {
		fmt.Fprintf(cmd.ErrOrStderr(), "format: want terminal|json\n")
		return 2
	}
	opts := auditor.Options{
		Target:        target,
		Titles:        loadTitles(),
		MinSeverity:   min,
		Excludes:      append(append([]string{}, cfg.Exclude.Paths...), excludes...),
		MaxBytes:      maxBytes,
		IncludeSSH:    only == catAll || only == catSSH,
		SSHConfigPath: sshCfgFlag,
	}
	if histFlag {
		opts.HistoryLimit = histLimit
	}
	if stagedFlag && only == catSecret {
		files, gerr := gitinspect.StagedFiles(target)
		if gerr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "git: %v\n", gerr)
			return 3
		}
		opts.Files = files
	}
	res, err := auditor.Run(opts)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "audit: %v\n", err)
		return 3
	}
	if only != catAll {
		kept := res.Findings[:0]
		for _, f := range res.Findings {
			if f.Category != string(only) {
				continue
			}
			if only == catGit {
				if stagedFlag && !strings.Contains(f.Evidence, "State: staged") {
					continue
				}
				if trackedFlag && !strings.Contains(f.Evidence, "State: tracked") {
					continue
				}
			}
			kept = append(kept, f)
		}
		res.Findings = kept
	}
	out := cmd.OutOrStdout()
	if format == "json" {
		if err := report.RenderJSON(out, res.Target, res.Findings); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "report: %v\n", err)
			return 3
		}
	} else if err := report.RenderTerminal(out, res.Target, res.Findings, quiet); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "report: %v\n", err)
		return 3
	}
	if verbose {
		fmt.Fprintf(out, "\nskipped %d paths, %d partial errors\n", len(res.Skipped), len(res.Partial))
		for _, perr := range res.Partial {
			fmt.Fprintf(out, "partial: %v\n", perr)
		}
	}
	return auditor.ExitCode(res)
}

func exitWith(cmd *cobra.Command, code int) error {
	if code != 0 {
		os.Exit(code)
	}
	return nil
}

func firstArg(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return "."
}

func auditCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "audit [path]",
		Short: "Run the full local audit",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return exitWith(cmd, runAudit(cmd, firstArg(args), catAll))
		},
	}
	c.Flags().BoolVar(&histFlag, "history", false, "include Git history")
	c.Flags().IntVar(&histLimit, "limit", 100, "max commits for history scan")
	return c
}

func secretsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "secrets [path]",
		Short: "Scan for possible secret exposure",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return exitWith(cmd, runAudit(cmd, firstArg(args), catSecret))
		},
	}
	c.Flags().BoolVar(&histFlag, "history", false, "include Git history")
	c.Flags().IntVar(&histLimit, "limit", 100, "max commits for history scan")
	c.Flags().BoolVar(&stagedFlag, "staged", false, "scan staged files only")
	return c
}

func permissionsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "permissions [path]",
		Short: "Check permissions and ownership of sensitive files",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return exitWith(cmd, runAudit(cmd, firstArg(args), catPermissions))
		},
	}
}

func sshCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "ssh",
		Short: "Audit local SSH client configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return exitWith(cmd, runAudit(cmd, ".", catSSH))
		},
	}
	c.Flags().StringVar(&sshCfgFlag, "config", "", "SSH config path (default ~/.ssh/config)")
	return c
}

func gitCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "git [path]",
		Short: "Audit sensitive files tracked by Git",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return exitWith(cmd, runAudit(cmd, firstArg(args), catGit))
		},
	}
	c.Flags().BoolVar(&stagedFlag, "staged", false, "show staged files only")
	c.Flags().BoolVar(&trackedFlag, "tracked", false, "show tracked files only")
	c.Flags().BoolVar(&histFlag, "history", false, "include Git history")
	c.Flags().IntVar(&histLimit, "limit", 100, "max commits for history scan")
	return c
}

func reportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "report",
		Short: "Re-run the audit and print the report (nothing is stored)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return exitWith(cmd, runAudit(cmd, ".", catAll))
		},
	}
}

func rulesCmd() *cobra.Command {
	rulesCmd := &cobra.Command{
		Use:   "rules",
		Short: "Inspect audit rules",
		Args:  cobra.NoArgs,
	}
	rulesCmd.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List available rules",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				rs, err := rules.LoadDir(rulesPath())
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "rules: %v\n", err)
					return nil
				}
				for _, r := range rules.Enabled(rs) {
					fmt.Fprintf(cmd.OutOrStdout(), "%-28s %-8s %s\n", r.ID, r.Severity, r.Title)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:   "explain <id>",
			Short: "Explain a specific rule",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				rs, err := rules.LoadDir(rulesPath())
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "rules: %v\n", err)
					return nil
				}
				r, ok := rules.ByID(rs, args[0])
				if !ok {
					fmt.Fprintf(cmd.ErrOrStderr(), "unknown rule %q\n", args[0])
					return nil
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Rule: %s\nSeverity: %s\n\n%s\n\nRecommended action:\n%s\n",
					r.ID, r.Severity, r.Title, r.Recommendation)
				return nil
			},
		},
	)
	return rulesCmd
}

func configCmd() *cobra.Command {
	cfg := &cobra.Command{
		Use:   "config",
		Short: "Manage configuration",
		Args:  cobra.NoArgs,
	}
	cfg.AddCommand(
		&cobra.Command{
			Use:   "init",
			Short: "Write the default configuration",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				home, err := os.UserHomeDir()
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "config init: %v\n", err)
					return nil
				}
				dir := filepath.Join(home, ".config", "mamori")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "config init: %v\n", err)
					return nil
				}
				raw, err := yaml.Marshal(config.Default())
				if err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "config init: %v\n", err)
					return nil
				}
				p := filepath.Join(dir, "config.yaml")
				if err := os.WriteFile(p, raw, 0o600); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "config init: %v\n", err)
					return nil
				}
				fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", p)
				return nil
			},
		},
	)
	return cfg
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version)
		},
	}
}
