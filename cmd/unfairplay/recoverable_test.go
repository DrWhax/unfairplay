package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRecoverableCommandsHelp(t *testing.T) {
	for _, name := range []string{"decrypt-recoverable", "encrypt"} {
		t.Run(name, func(t *testing.T) {
			c := newRootCommand()
			var b bytes.Buffer
			c.SetOut(&b)
			c.SetErr(&b)
			c.SetArgs([]string{name, "-h"})
			if e := c.Execute(); e != nil {
				t.Fatal(e)
			}
			for _, want := range []string{"--input", "--output", "--model", "--help", ".sinf-recovery"} {
				if !strings.Contains(b.String(), want) {
					t.Fatalf("missing help: %s", want)
				}
			}
		})
	}
}

func TestRecoverableDefaultSuffixHelp(t *testing.T) {
	c := newRecoverableCommand(false)
	if !strings.Contains(c.Flags().Lookup("output").Usage, ".decrypted-recoverable.ipa") {
		t.Fatal("incorrect default suffix")
	}
}
