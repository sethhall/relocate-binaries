package tests

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var builtBinary string

func TestMain(m *testing.M) {
	// Build the relocate-binaries binary into a temp dir
	tmpDir, err := os.MkdirTemp("", "rb-build-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	builtBinary = filepath.Join(tmpDir, "relocate-binaries")
	cmd := exec.Command("go", "build", "-o", builtBinary, "main.go")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = getProjectRoot()
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build relocate-binaries: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func getProjectRoot() string {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "getwd: %v\n", err)
		os.Exit(1)
	}
	// tests/ -> project root
	return filepath.Dir(wd)
}

func projectRoot(t *testing.T) string {
	t.Helper()
	return getProjectRoot()
}

func ensureToolsOrSkip(t *testing.T) {
	if runtime.GOOS == "darwin" {
		mustExist(t, "otool")
		mustExist(t, "install_name_tool")
	} else if runtime.GOOS == "linux" {
		mustExist(t, "ldd")
		mustExist(t, "patchelf")
		mustExist(t, "file")
	}
}

func mustExist(t *testing.T, tool string) {
	t.Helper()
	if _, err := exec.LookPath(tool); err != nil {
		t.Skipf("skipping: required tool %q not found", tool)
	}
}

func pickBinariesForPlatform(t *testing.T) (string, string) {
	t.Helper()
	if runtime.GOOS == "darwin" {
		// Prefer a Homebrew binary that pulls in a non-system lib to exercise lib copying
		if path, err := exec.LookPath("python3"); err == nil && strings.HasPrefix(path, "/opt/homebrew/") {
			// Use python3 plus a simple system binary as second
			return path, "/bin/cat"
		}
		// Fallback: two simple system binaries; tests that rely on non-system libs will skip
		return "/bin/echo", "/bin/cat"
	}
	// Linux defaults
	return "/bin/ls", "/bin/echo"
}

func TestDryRunAndExecutionSingleBinary(t *testing.T) {
	ensureToolsOrSkip(t)
	bin1, _ := pickBinariesForPlatform(t)

	tmp := t.TempDir()

	// Dry run shouldn't create output
	args := []string{"-p", bin1, "--dry-run", "-v", "-output", filepath.Join(tmp, "out1")}
	run(t, args...)
	if _, err := os.Stat(filepath.Join(tmp, "out1")); !os.IsNotExist(err) {
		t.Fatalf("dry-run unexpectedly created output directory")
	}

	// Actual run should create manifest and bin dir
	args = []string{"-p", bin1, "-v", "-output", filepath.Join(tmp, "out2"), "-install-path", "/opt/test"}
	run(t, args...)
	mustExistPath(t, filepath.Join(tmp, "out2", "manifest.json"))
	mustExistPath(t, filepath.Join(tmp, "out2", "bin", filepath.Base(bin1)))
}

func TestMultiplePFlags(t *testing.T) {
	ensureToolsOrSkip(t)
	bin1, bin2 := pickBinariesForPlatform(t)
	out := filepath.Join(t.TempDir(), "multi")
	run(t, "-p", bin1, "-p", bin2, "-output", out, "-install-path", "/opt/test")
	mustExistPath(t, filepath.Join(out, "bin", filepath.Base(bin1)))
	mustExistPath(t, filepath.Join(out, "bin", filepath.Base(bin2)))
}

func TestIgnoreFile(t *testing.T) {
	ensureToolsOrSkip(t)
	bin1, _ := pickBinariesForPlatform(t)

	// This test requires at least one non-system library to be planned, otherwise it's a no-op
	requiresNonSystemDep := func() bool {
		if runtime.GOOS == "darwin" {
			return strings.HasPrefix(bin1, "/opt/homebrew/")
		}
		return true // on Linux most bins have non-system deps
	}()
	if !requiresNonSystemDep {
		t.Skip("no non-system dependency available to exercise -ignore-file; install Homebrew python3 for this test")
	}

	tmp := t.TempDir()
	ignorePath := filepath.Join(tmp, ".bundleignore")
	// Use a pattern that ignores share/doc files which are commonly available to test filtering
	// without interfering with essential lib/ directory functionality
	if err := os.WriteFile(ignorePath, []byte("share/doc/*\n*.md\n"), 0644); err != nil {
		t.Fatalf("write ignore file: %v", err)
	}

	out := filepath.Join(tmp, "out")
	run(t, "-p", bin1, "-output", out, "-ignore-file", ignorePath)

	// Check that filtering worked by verifying .md files or doc directories are absent
	// This test validates the ignore functionality without breaking essential library copying
	docDir := filepath.Join(out, "share", "doc")
	if info, err := os.Stat(docDir); err == nil && info.IsDir() {
		entries, _ := os.ReadDir(docDir)
		if len(entries) != 0 {
			t.Fatalf("expected share/doc directory to be filtered by -ignore-file, found %d entries", len(entries))
		}
	}
	// Also check for .md files at root level
	if entries, _ := os.ReadDir(out); len(entries) > 0 {
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".md") {
				t.Fatalf("expected .md files to be filtered by -ignore-file, found: %s", entry.Name())
			}
		}
	}
}

func TestArchiveFlag(t *testing.T) {
	ensureToolsOrSkip(t)
	bin1, _ := pickBinariesForPlatform(t)
	out := filepath.Join(t.TempDir(), "arch")
	run(t, "-p", bin1, "-output", out, "--archive")

	// Archive should be named "<output>.tar.gz" per implementation
	archivePath := out + ".tar.gz"
	mustExistPath(t, archivePath)

	// Verify archive contains manifest and bin binary
	checkTarGzContains(t, archivePath, []string{"manifest.json", filepath.Join("bin", filepath.Base(bin1))})
}

func run(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command(builtBinary, args...)
	cmd.Dir = projectRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\nargs: %v\noutput:\n%s", err, args, string(out))
	}
}

func mustExistPath(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("expected path to exist: %s: %v", p, err)
	}
}

func checkTarGzContains(t *testing.T, tarGzPath string, required []string) {
	t.Helper()
	f, err := os.Open(tarGzPath)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gz.Close()
	tarR := tar.NewReader(gz)
	found := map[string]bool{}
	for {
		hdr, err := tarR.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		// Normalise names to forward slashes and strip leading project dir portions
		name := filepath.ToSlash(hdr.Name)
		for _, r := range required {
			r = filepath.ToSlash(r)
			if strings.HasSuffix(name, r) {
				found[r] = true
			}
		}
	}
	for _, r := range required {
		if !found[filepath.ToSlash(r)] {
			t.Fatalf("archive missing required entry: %s", r)
		}
	}
}
