package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/DrWhax/unfairplay/pkg/fairplay"
	"github.com/spf13/cobra"
)

func newConvertDecryptedIPAMacOSCommand() *cobra.Command {
	var options fairplay.MacOSAppOptions
	command := &cobra.Command{
		Use:   "convert-decrypted-ipa-macos",
		Short: "Build a locally signed macOS app from a decrypted IPA (Apple silicon)",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if !strings.EqualFold(filepath.Ext(options.InputPath), ".ipa") {
				return fmt.Errorf("input must be a decrypted IPA")
			}
			if options.OutputPath == "" {
				options.OutputPath = strings.TrimSuffix(options.InputPath, filepath.Ext(options.InputPath)) + ".macos.app"
			}
			result, err := fairplay.ConvertDecryptedIPAToMacOS(command.Context(), options)
			if err != nil {
				return err
			}
			return printJSON(result)
		},
	}
	command.Flags().StringVar(&options.InputPath, "input", "", "Already decrypted IPA")
	command.Flags().StringVar(&options.OutputPath, "output", "", "New .app directory (defaults to <input>.macos.app)")
	_ = command.MarkFlagRequired("input")
	return command
}
