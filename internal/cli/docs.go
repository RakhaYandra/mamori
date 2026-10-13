package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

func completionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Print shell completion scripts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := cmd.Root()
			out := cmd.OutOrStdout()
			switch args[0] {
			case "bash":
				return root.GenBashCompletionV2(out, true)
			case "zsh":
				return root.GenZshCompletion(out)
			case "fish":
				return root.GenFishCompletion(out, true)
			case "powershell":
				return root.GenPowerShellCompletion(out)
			default:
				return fmt.Errorf("unknown shell %q: want bash|zsh|fish|powershell", args[0])
			}
		},
	}
}

func manCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "man",
		Short: "Generate man pages for mamori and subcommands",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, _ := cmd.Flags().GetString("dir")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			header := &doc.GenManHeader{Title: "MAMORI", Section: "1"}
			return doc.GenManTree(cmd.Root(), header, dir)
		},
	}
	c.Flags().String("dir", "", "output directory for man pages (required)")
	_ = c.MarkFlagRequired("dir")
	return c
}
