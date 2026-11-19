package main

import (
	"path/filepath"
	"strings"

	"github.com/DrWhax/unfairplay/pkg/recoverable"
	"github.com/spf13/cobra"
)

func newRecoverableCommand(encrypt bool) *cobra.Command {
	var o recoverable.Options
	name, short, suffix := "decrypt-recoverable", "Decrypt an IPA and retain its application recovery key", ".decrypted-recoverable.ipa"
	if encrypt {
		name = "encrypt"
		short = "Restore an enhanced IPA using the destination enrollment model"
		suffix = ".encrypted.ipa"
	}
	c := &cobra.Command{Use: name, Short: short, Args: cobra.NoArgs, Long: short + ".\n\nThe enhanced IPA stores one versioned <executable>.sinf-recovery in the main SC_Info.\nSource application fields, private IV and full rights trailer are preserved.\nEncryption removes the recovery file and creates destination SINF licenses.\nOlder key-only and two-file recovery archives must be regenerated.\nOriginal unencrypted components are preserved. Outputs must be new files.\nEncryption needs no source account model or external decryption report.\nCurrently supports one source license, game content with medi=128, and v2 models.\nA saved model directory must contain exactly one model; otherwise use --model.", RunE: func(_ *cobra.Command, _ []string) error {
		mp, e := selectedModelPath(o.ModelPath)
		if e != nil {
			return e
		}
		o.ModelPath = mp
		if o.OutputPath == "" {
			o.OutputPath = strings.TrimSuffix(o.InputPath, filepath.Ext(o.InputPath)) + suffix
		}
		var r recoverable.Result
		if encrypt {
			r, e = recoverable.Encrypt(o)
		} else {
			r, e = recoverable.Decrypt(o)
		}
		if e != nil {
			return e
		}
		return printJSON(r)
	}}
	c.Flags().StringVar(&o.InputPath, "input", "", "Input IPA")
	c.Flags().StringVar(&o.OutputPath, "output", "", "New output IPA (default: input stem"+suffix+")")
	c.Flags().StringVar(&o.ModelPath, "model", "", "Enrollment model file or directory (default: saved models)")
	_ = c.MarkFlagRequired("input")
	return c
}
