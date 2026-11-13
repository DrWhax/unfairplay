package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/DrWhax/unfairplay/pkg/fairplay"
	"github.com/DrWhax/unfairplay/pkg/setup"
	"github.com/spf13/cobra"
)

var version = "dev"

func executableVersion() string {
	if version != "dev" {
		return version
	}
	information, ok := debug.ReadBuildInfo()
	if !ok {
		return version
	}
	revision, modified := "", false
	for _, setting := range information.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if revision == "" {
		return version
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified {
		revision += "-dirty"
	}
	return version + "-" + revision
}

func main() {
	root := newRootCommand()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "unfairplay",
		Short:         "Recover native Mac FairPlay enrollment and decrypt personalized IPAs",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       executableVersion(),
	}
	root.AddCommand(newSetupCommand(), newCollectCommand(), newRecoverCommand(), newDecryptCommand(), newConvertIPAMacOSCommand(), newConvertDecryptedIPAMacOSCommand(), newVerifyCommand(), newDoctorCommand())
	return root
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func newCollectCommand() *cobra.Command {
	var options fairplay.EnrollmentCollectOptions
	command := &cobra.Command{
		Use:   "collect",
		Short: "Collect one private native Mac App Store enrollment bundle",
		RunE: func(_ *cobra.Command, _ []string) error {
			manifest, err := fairplay.CollectEnrollment(options)
			if err != nil {
				return err
			}
			return printJSON(map[string]any{
				"success": true, "capture": options.OutputPath, "build": manifest.FairPlay.Build,
				"support": manifest.FairPlay.Status, "selector": manifest.App.SelectorID,
				"files": len(manifest.Files),
			})
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.AppPath, "app", "", "Native App Store-installed .app path")
	flags.StringVar(&options.InstalledExecutablePath, "installed-executable-path", "", "Original absolute executable path for an archived app")
	flags.StringVar(&options.IPAPath, "ipa", "", "Matching personalized encrypted IPA")
	flags.StringVar(&options.OutputPath, "output", "", "New private capture directory")
	flags.StringVar(&options.SystemStatePath, "system-state", "", "System SC Info directory")
	flags.StringVar(&options.SharedStatePath, "shared-state", "", "Shared SC Info directory")
	flags.StringVar(&options.ADIPath, "adi-state", "", "Native ADI state directory")
	flags.StringVar(&options.MACAddressPath, "iomac-file", "", "Private six-byte IOMACAddress file")
	flags.StringVar(&options.HardwareInterface, "interface", "en0", "Built-in IORegistry network interface")
	flags.StringVar(&options.ProductVersion, "product-version", "", "Archived source macOS product version")
	flags.StringVar(&options.BuildVersion, "build-version", "", "Archived source macOS build version")
	_ = command.MarkFlagRequired("app")
	_ = command.MarkFlagRequired("output")
	return command
}

func newRecoverCommand() *cobra.Command {
	var options setup.RecoverOptions
	command := &cobra.Command{
		Use:   "recover",
		Short: "Recover and validate a private enrollment model from a capture",
		RunE: func(command *cobra.Command, _ []string) error {
			return recoverEnrollment(command.Context(), options)
		},
	}
	command.Flags().StringVar(&options.Capture, "capture", "", "Private capture directory")
	command.Flags().StringVar(&options.Output, "output", "", "New private recovery directory")
	_ = command.MarkFlagRequired("capture")
	_ = command.MarkFlagRequired("output")
	return command
}

type decryptOptions struct {
	Input, Output, Report, Model string
	Force, StripAccountData      bool
}

func newDecryptCommand() *cobra.Command {
	var options decryptOptions
	command := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt a personalized IPA with a recovered enrollment model",
		RunE: func(_ *cobra.Command, _ []string) error {
			if !strings.EqualFold(filepath.Ext(options.Input), ".ipa") {
				return errors.New("input must be an IPA")
			}
			modelPath, err := selectedModelPath(options.Model)
			if err != nil {
				return err
			}
			stem := strings.TrimSuffix(options.Input, filepath.Ext(options.Input))
			if options.Output == "" {
				options.Output = stem + ".decrypted.ipa"
			}
			if options.Report == "" {
				options.Report = stem + ".decrypted.json"
			}
			result, err := fairplay.DecryptIPA(fairplay.DecryptOptions{
				InputPath: options.Input, OutputPath: options.Output, ReportPath: options.Report,
				ModelPath: modelPath, Force: options.Force, StripAccountData: options.StripAccountData,
			})
			if err != nil {
				return err
			}
			return printJSON(result)
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.Input, "input", "", "Personalized encrypted IPA")
	flags.StringVar(&options.Output, "output", "", "Decrypted analysis IPA path")
	flags.StringVar(&options.Report, "report", "", "Private decryption report path")
	flags.StringVar(&options.Model, "model", "", "Private enrollment model file or directory (defaults to saved models)")
	flags.BoolVar(&options.Force, "force", false, "Replace existing output and report")
	flags.BoolVar(&options.StripAccountData, "strip-account-data", false, "Omit SC_Info licenses and remove Apple ID fields from iTunesMetadata.plist in the output")
	_ = command.MarkFlagRequired("input")
	return command
}

type convertIPAMacOSOptions struct {
	Input, Output, Credential, Model string
	Force                            bool
}

func newConvertIPAMacOSCommand() *cobra.Command {
	var options convertIPAMacOSOptions
	command := &cobra.Command{
		Use:   "convert-ipa-macos",
		Short: "Convert a personalized encrypted IPA for macOS FairPlay",
		RunE: func(_ *cobra.Command, _ []string) error {
			if !strings.EqualFold(filepath.Ext(options.Input), ".ipa") {
				return errors.New("input must be an IPA")
			}
			if options.Credential != "" && options.Model != "" {
				return errors.New("pass either --credential or --model, not both")
			}
			if options.Credential == "" {
				modelPath, err := selectedModelPath(options.Model)
				if err != nil {
					return err
				}
				options.Model = modelPath
			}
			stem := strings.TrimSuffix(options.Input, filepath.Ext(options.Input))
			if options.Output == "" {
				options.Output = stem + ".macos.ipa"
			}
			result, err := fairplay.PrepareMacOSIPA(fairplay.MacOSPrepareOptions{
				InputPath: options.Input, OutputPath: options.Output,
				CredentialPath: options.Credential, ModelPath: options.Model, Force: options.Force,
			})
			if err != nil {
				return err
			}
			return printJSON(result)
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.Input, "input", "", "Personalized encrypted IPA")
	flags.StringVar(&options.Output, "output", "", "Converted encrypted IPA path")
	flags.StringVar(&options.Model, "model", "", "Private version-2 enrollment model or directory (defaults to saved models)")
	flags.StringVar(&options.Credential, "credential", "", "Private 16-byte account credential instead of a model")
	flags.BoolVar(&options.Force, "force", false, "Replace existing output")
	_ = command.MarkFlagRequired("input")
	return command
}

func verificationSummary(result fairplay.DecryptResult) map[string]any {
	summary := map[string]any{
		"schema": "unfairplay-model-verification-v2", "success": true,
		"decrypted_ipa_sha256": result.OutputSHA256,
		"encrypted_images":     result.EncryptedImages, "decrypted_pages": result.DecryptedPages,
		"logical_key_sha256_by_sinf": result.LogicalKeySHA256BySINF,
		"plaintext_retained":         false,
		"plaintext_verified":         result.PlaintextVerified,
	}
	if result.LogicalKeySHA256 != "" {
		summary["schema"] = "unfairplay-model-verification-v1"
		summary["logical_key_sha256"] = result.LogicalKeySHA256
	}
	return summary
}

func newVerifyCommand() *cobra.Command {
	var inputPath, modelPath string
	command := &cobra.Command{
		Use:   "verify",
		Short: "Validate an enrollment model against an IPA without retaining plaintext",
		RunE: func(_ *cobra.Command, _ []string) error {
			if !strings.EqualFold(filepath.Ext(inputPath), ".ipa") {
				return errors.New("input must be an IPA")
			}
			selectedModel, err := selectedModelPath(modelPath)
			if err != nil {
				return err
			}
			temporary, err := os.MkdirTemp("", "unfairplay-verify-*")
			if err != nil {
				return err
			}
			cleaned := false
			defer func() {
				if !cleaned {
					_ = os.RemoveAll(temporary)
				}
			}()
			if err := os.Chmod(temporary, 0o700); err != nil {
				return err
			}
			result, err := fairplay.DecryptIPA(fairplay.DecryptOptions{
				InputPath: inputPath, ModelPath: selectedModel,
				OutputPath: filepath.Join(temporary, "App.decrypted.ipa"),
				ReportPath: filepath.Join(temporary, "App.decrypted.json"),
			})
			if err != nil {
				return err
			}
			if err := os.RemoveAll(temporary); err != nil {
				return fmt.Errorf("remove temporary plaintext: %w", err)
			}
			cleaned = true
			return printJSON(verificationSummary(result))
		},
	}
	command.Flags().StringVar(&inputPath, "input", "", "Personalized encrypted IPA")
	command.Flags().StringVar(&modelPath, "model", "", "Private enrollment model file or directory (defaults to saved models)")
	_ = command.MarkFlagRequired("input")
	return command
}

func newDoctorCommand() *cobra.Command {
	var capture, ipa, model, reportPath string
	command := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose capture, SINF, model, and evaluator support",
		RunE: func(_ *cobra.Command, _ []string) error {
			report := fairplay.DoctorFairPlay(capture, ipa, model)
			if reportPath != "" {
				if err := fairplay.WriteDoctorReport(reportPath, report); err != nil {
					return err
				}
			}
			if err := printJSON(report); err != nil {
				return err
			}
			if len(report.Errors) != 0 {
				return errors.New("diagnostic checks failed")
			}
			return nil
		},
	}
	flags := command.Flags()
	flags.StringVar(&capture, "capture", "", "Private enrollment capture directory")
	flags.StringVar(&ipa, "ipa", "", "Personalized encrypted IPA")
	flags.StringVar(&model, "model", "", "Private enrollment model file or directory")
	flags.StringVar(&reportPath, "report", "", "New private JSON diagnostic report")
	return command
}

func recoverEnrollment(ctx context.Context, options setup.RecoverOptions) error {
	options.Progress = printRecoveryProgress
	result, err := setup.Recover(ctx, options)
	if err != nil {
		return err
	}
	return printJSON(result.Summary)
}

func printRecoveryProgress(line string) {
	fmt.Fprintf(os.Stderr, "recovery build=%s %s\n", executableVersion(), line)
}
