package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	"github.com/DrWhax/unfairplay/pkg/setup"
	"github.com/spf13/cobra"
)

const modelDirectoryEnvironment = "UNFAIRPLAY_MODEL_DIR"

func defaultModelDirectory() (string, error) {
	if configured := os.Getenv(modelDirectoryEnvironment); configured != "" {
		return filepath.Abs(configured)
	}
	var base string
	if os.Geteuid() == 0 && os.Getenv("SUDO_USER") != "" {
		account, err := user.Lookup(os.Getenv("SUDO_USER"))
		if err != nil || account.HomeDir == "" {
			return "", fmt.Errorf("find invoking user configuration directory")
		}
		switch runtime.GOOS {
		case "darwin":
			base = filepath.Join(account.HomeDir, "Library", "Application Support")
		default:
			base = filepath.Join(account.HomeDir, ".config")
		}
	} else {
		var err error
		base, err = os.UserConfigDir()
		if err != nil {
			return "", err
		}
	}
	return filepath.Join(base, "unfairplay", "models"), nil
}

func selectedModelPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	directory, err := defaultModelDirectory()
	if err != nil {
		return "", err
	}
	info, err := os.Stat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("no saved enrollment models; run unfairplay setup or pass --model")
	}
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("saved enrollment model path is not a directory: %s", directory)
	}
	return directory, nil
}

func newSetupCommand() *cobra.Command {
	var options setup.Options
	command := &cobra.Command{
		Use:   "setup",
		Short: "Set up reusable IPA decryption from one installed app",
		RunE: func(command *cobra.Command, _ []string) error {
			return runSetup(command.Context(), options)
		},
	}
	flags := command.Flags()
	flags.StringVar(&options.AppPath, "app", "", "Native Mac App Store-installed .app path")
	flags.StringVar(&options.IPAPath, "ipa", "", "Matching personalized encrypted IPA")
	flags.StringVar(&options.ModelDirectory, "model-dir", "", "Private model directory (defaults to the user configuration directory)")
	flags.StringVar(&options.HardwareInterface, "interface", "en0", "Built-in IORegistry network interface")
	flags.BoolVar(&options.KeepWork, "keep-work", false, "Keep the private capture and validation files")
	_ = command.MarkFlagRequired("app")
	_ = command.MarkFlagRequired("ipa")
	return command
}

func runSetup(ctx context.Context, options setup.Options) error {
	if options.ModelDirectory == "" {
		directory, err := defaultModelDirectory()
		if err != nil {
			return err
		}
		options.ModelDirectory = directory
	}
	options.Progress = printRecoveryProgress
	result, err := setup.Run(ctx, options)
	if err != nil {
		return err
	}
	return printJSON(result.Summary)
}
