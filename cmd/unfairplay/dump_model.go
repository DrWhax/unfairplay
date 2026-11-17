package main

import (
	"fmt"
	"os"

	"github.com/DrWhax/unfairplay/pkg/fairplay"
	"github.com/spf13/cobra"
)

func newDumpModelCommand() *cobra.Command {
	var format string
	var raw bool
	command := &cobra.Command{
		Use:   "dump-model <model.bin>",
		Short: "Print every field of an enrollment model, including its secret key",
		Long: "Print every field of an enrollment model file, including the secret key\n" +
			"and lookup tables. The output can decrypt every app from the enrollment;\n" +
			"treat it exactly like the model file itself.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			dump, err := fairplay.DumpEnrollmentModel(args[0], raw)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				return printJSON(dump)
			case "text":
				return fairplay.WriteModelDumpText(os.Stdout, dump)
			default:
				return fmt.Errorf("unknown --format %q (want text or json)", format)
			}
		},
	}
	flags := command.Flags()
	flags.StringVar(&format, "format", "text", "Output format: text or json")
	flags.BoolVar(&raw, "raw", false, "Also include a hex dump of the whole file")
	return command
}
