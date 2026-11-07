package fairplay

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func testFile(t *testing.T, directory, name, contents string) string {
	t.Helper()
	name = filepath.Join(directory, name)
	if err := os.WriteFile(name, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

func assertFile(t *testing.T, name, want string) {
	t.Helper()
	got, err := os.ReadFile(name)
	if err != nil || string(got) != want {
		t.Fatalf("read %s: got %q, %v; want %q", name, got, err, want)
	}
}

func testOptions(t *testing.T) DecryptOptions {
	t.Helper()
	dir := t.TempDir()
	return DecryptOptions{
		InputPath:  testFile(t, dir, "input.ipa", "source"),
		OutputPath: filepath.Join(dir, "output.ipa"), ReportPath: filepath.Join(dir, "report.json"),
	}
}

func TestValidatePathsProtectsEveryInput(t *testing.T) {
	for _, force := range []bool{false, true} {
		for _, report := range []bool{false, true} {
			options := testOptions(t)
			options.Force = force
			if report {
				options.ReportPath = options.InputPath
			} else {
				options.OutputPath = options.InputPath
			}
			if _, err := validatePaths(options); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
				t.Fatalf("force=%v report=%v: %v", force, report, err)
			}
			assertFile(t, options.InputPath, "source")
		}
	}
}

func TestValidatePathsProtectsEnrollmentModel(t *testing.T) {
	options := testOptions(t)
	options.Force = true
	options.ModelPath = testFile(t, filepath.Dir(options.InputPath), "enrollment.bin", "private model")
	options.OutputPath = options.ModelPath
	if _, err := validatePaths(options); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("model overwrite was accepted: %v", err)
	}
	assertFile(t, options.ModelPath, "private model")
}

func TestValidatePathsRejectsDestinationCollisions(t *testing.T) {
	options := testOptions(t)
	options.ReportPath = options.OutputPath
	if _, err := validatePaths(options); err == nil {
		t.Fatal("accepted identical output and report")
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		options.ReportPath = filepath.Join(filepath.Dir(options.OutputPath), "OUTPUT.IPA")
		if _, err := validatePaths(options); err == nil {
			t.Fatal("accepted case aliases")
		}
	}
}

func TestValidatePathsResolvesFilesystemAliases(t *testing.T) {
	options := testOptions(t)
	options.Force = true
	if err := os.Link(options.InputPath, options.OutputPath); err != nil {
		t.Fatal(err)
	}
	if _, err := validatePaths(options); err == nil {
		t.Fatal("accepted a hardlink to the input")
	}
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation can require Windows privileges")
	}
	options = testOptions(t)
	options.Force = true
	dir := filepath.Dir(options.InputPath)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	options.OutputPath = filepath.Join(alias, filepath.Base(options.InputPath))
	if _, err := validatePaths(options); err == nil {
		t.Fatal("accepted input through a directory symlink")
	}
	options.OutputPath = filepath.Join(alias, "new", "output.ipa")
	options.ReportPath = filepath.Join(dir, "new", "output.ipa")
	if _, err := validatePaths(options); err == nil {
		t.Fatal("accepted aliased new destinations")
	}
}

func TestValidatePathsRejectsSymlinkAndDirectoryDestinations(t *testing.T) {
	options := testOptions(t)
	options.Force = true
	options.OutputPath = t.TempDir()
	if _, err := validatePaths(options); err == nil {
		t.Fatal("accepted a directory destination")
	}
	if runtime.GOOS == "windows" {
		return
	}
	options.OutputPath = filepath.Join(t.TempDir(), "dangling")
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), options.OutputPath); err != nil {
		t.Fatal(err)
	}
	if _, err := validatePaths(options); err == nil {
		t.Fatal("accepted a dangling destination symlink")
	}
}

func TestPublishFilesRollsBackOnSecondFailure(t *testing.T) {
	for _, force := range []bool{false, true} {
		dir := t.TempDir()
		first := stagedFile{testFile(t, dir, "stage-one", "new IPA"), filepath.Join(dir, "output.ipa")}
		second := stagedFile{testFile(t, dir, "stage-two", "new report"), filepath.Join(dir, "report.json")}
		if force {
			testFile(t, dir, "output.ipa", "previous IPA")
			// A destination became a directory after the earlier validation.
			if err := os.Mkdir(second.destination, 0o700); err != nil {
				t.Fatal(err)
			}
		} else {
			testFile(t, dir, "report.json", "another writer's report")
		}
		if err := publishFiles([]stagedFile{first, second}, force); err == nil {
			t.Fatal("expected publication failure")
		}
		if force {
			assertFile(t, first.destination, "previous IPA")
		} else {
			if _, err := os.Stat(first.destination); !os.IsNotExist(err) {
				t.Fatalf("partial output remains: %v", err)
			}
			assertFile(t, second.destination, "another writer's report")
		}
		backups, err := filepath.Glob(filepath.Join(dir, ".fairplay-backup-*"))
		if err != nil || len(backups) != 0 {
			t.Fatalf("unexpected recovery files: %v, %v", backups, err)
		}
	}
}

func TestPublishFilesNoClobberWithConcurrentWriters(t *testing.T) {
	dir := t.TempDir()
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, contents := range []string{"one", "two"} {
		files := []stagedFile{
			{testFile(t, dir, contents+"-ipa", contents), filepath.Join(dir, "output.ipa")},
			{testFile(t, dir, contents+"-report", contents), filepath.Join(dir, "report.json")},
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			results <- publishFiles(files, false)
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("got %d successful writers, want one", winners)
	}
	output, err := os.ReadFile(filepath.Join(dir, "output.ipa"))
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(dir, "report.json"), string(output))
}

func TestPublishFilesReplacesPairWithForce(t *testing.T) {
	dir := t.TempDir()
	files := []stagedFile{
		{testFile(t, dir, "stage-ipa", "new IPA"), testFile(t, dir, "output.ipa", "old IPA")},
		{testFile(t, dir, "stage-report", "new report"), testFile(t, dir, "report.json", "old report")},
	}
	if err := publishFiles(files, true); err != nil {
		t.Fatal(err)
	}
	assertFile(t, files[0].destination, "new IPA")
	assertFile(t, files[1].destination, "new report")
}
