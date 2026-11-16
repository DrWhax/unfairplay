package main

import (
	"github.com/DrWhax/unfairplay/pkg/fairplay"
	"github.com/DrWhax/unfairplay/pkg/setup"
	"github.com/spf13/cobra"
)

func newExportEnrollmentCommand() *cobra.Command {
	var options fairplay.EnrollmentExportOptions
	var output string
	command := &cobra.Command{
		Use: "export-enrollment", Short: "Export private Mac enrollment state without selecting an app", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			summary, err := setup.ExportEnrollment(cmd.Context(), options, output)
			if err != nil {
				return err
			}
			return printJSON(summary)
		},
	}
	f := command.Flags()
	f.StringVar(&output, "output", "", "New private snapshot file in an existing directory (never overwritten)")
	f.StringVar(&options.SystemStatePath, "system-state", "", "System SC Info directory")
	f.StringVar(&options.SharedStatePath, "shared-state", "", "Shared SC Info directory")
	f.StringVar(&options.MACAddressPath, "iomac-file", "", "Private six-byte IOMACAddress file for archived state")
	f.StringVar(&options.HardwareInterface, "interface", "en0", "Built-in IORegistry network interface")
	f.StringVar(&options.ProductVersion, "product-version", "", "Archived source macOS product version")
	f.StringVar(&options.BuildVersion, "build-version", "", "Archived source macOS build version")
	_ = command.MarkFlagRequired("output")
	return command
}
