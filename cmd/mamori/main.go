// Command mamori is a local-first Linux security auditor for developer machines.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
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

func auditCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "audit [path]",
		Short: "Run the full local audit",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "mamori audit: not implemented yet (P1)")
			return nil
		},
	}
}

func secretsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "secrets [path]",
		Short: "Scan for possible secret exposure",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "mamori secrets: not implemented yet (P1)")
			return nil
		},
	}
	c.Flags().Bool("history", false, "include Git history")
	c.Flags().Bool("staged", false, "scan staged files only")
	return c
}

func permissionsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "permissions [path]",
		Short: "Check permissions and ownership of sensitive files",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "mamori permissions: not implemented yet (P1)")
			return nil
		},
	}
}

func sshCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "ssh",
		Short: "Audit local SSH client configuration",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "mamori ssh: not implemented yet (P1)")
			return nil
		},
	}
	c.Flags().String("config", "", "SSH config path (default ~/.ssh/config)")
	return c
}

func gitCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "git [path]",
		Short: "Audit sensitive files tracked by Git",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "mamori git: not implemented yet (P1)")
			return nil
		},
	}
	c.Flags().Bool("staged", false, "check staged files")
	c.Flags().Bool("tracked", false, "check tracked files")
	return c
}

func reportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "report",
		Short: "Show or export the last audit report",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "mamori report: not implemented yet (P1)")
			return nil
		},
	}
}

func rulesCmd() *cobra.Command {
	rules := &cobra.Command{
		Use:   "rules",
		Short: "Inspect audit rules",
		Args:  cobra.NoArgs,
	}
	rules.AddCommand(
		&cobra.Command{
			Use:   "list",
			Short: "List available rules",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Fprintln(cmd.OutOrStdout(), "mamori rules list: not implemented yet (P1)")
				return nil
			},
		},
		&cobra.Command{
			Use:   "explain <id>",
			Short: "Explain a specific rule",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				fmt.Fprintln(cmd.OutOrStdout(), "mamori rules explain: not implemented yet (P1)")
				return nil
			},
		},
	)
	return rules
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
				fmt.Fprintln(cmd.OutOrStdout(), "mamori config init: not implemented yet (P1)")
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
