package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestIsSystemDLL tests the Windows system DLL detection
func TestIsSystemDLL(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	tests := []struct {
		name     string
		dllPath  string
		expected bool
	}{
		{"kernel32", `C:\Windows\System32\kernel32.dll`, true},
		{"ntdll", `C:\Windows\System32\ntdll.dll`, true},
		{"user32", `C:\WINDOWS\SYSTEM32\user32.dll`, true}, // Case insensitive
		{"custom dll in windows", `C:\Windows\mycustom.dll`, true},
		{"custom dll elsewhere", `C:\myapp\mylib.dll`, false},
		{"msvcrt by name", `C:\custom\msvcrt.dll`, true}, // Known system DLL by name
		{"vcruntime in app dir", `C:\app\vcruntime140.dll`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSystemDLL(tt.dllPath)
			if result != tt.expected {
				t.Errorf("isSystemDLL(%q) = %v, want %v", tt.dllPath, result, tt.expected)
			}
		})
	}
}

// TestIsSystemPath tests system directory detection
func TestIsSystemPath(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"Windows dir", `C:\Windows\notepad.exe`, true},
		{"Program Files", `C:\Program Files\SomeApp\app.exe`, true},
		{"Program Files x86", `C:\Program Files (x86)\OtherApp\app.exe`, true},
		{"Custom app", `C:\MyApps\tool.exe`, false},
		{"User directory", `C:\Users\john\app.exe`, false},
		{"Case insensitive", `c:\windows\system32\cmd.exe`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSystemPath(tt.path)
			if result != tt.expected {
				t.Errorf("isSystemPath(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

// TestGetStandaloneInstallRoot tests install root detection
func TestGetStandaloneInstallRoot(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	// Create a realistic install structure
	tempDir := t.TempDir()
	installRoot := filepath.Join(tempDir, "zeek-install")
	binDir := filepath.Join(installRoot, "bin")
	shareDir := filepath.Join(installRoot, "share")

	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(shareDir, 0755); err != nil {
		t.Fatal(err)
	}

	testExe := filepath.Join(binDir, "zeek.exe")
	if err := os.WriteFile(testExe, []byte{}, 0755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "valid install",
			path:     testExe,
			expected: installRoot,
		},
		{
			name:     "not in bin dir",
			path:     filepath.Join(tempDir, "random", "app.exe"),
			expected: "",
		},
		{
			name:     "bin dir without siblings",
			path:     filepath.Join(tempDir, "lonely", "bin", "app.exe"),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getStandaloneInstallRoot(tt.path)
			if result != tt.expected {
				t.Errorf("getStandaloneInstallRoot(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

// TestIsStandaloneWindowsInstall tests the complete detection logic
func TestIsStandaloneWindowsInstall(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	// Create test install structure
	tempDir := t.TempDir()
	installRoot := filepath.Join(tempDir, "suricata-install")
	binDir := filepath.Join(installRoot, "bin")
	etcDir := filepath.Join(installRoot, "etc")

	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		t.Fatal(err)
	}

	testExe := filepath.Join(binDir, "suricata.exe")
	if err := os.WriteFile(testExe, []byte{}, 0755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "valid standalone install",
			path:     testExe,
			expected: true,
		},
		{
			name:     "system path",
			path:     `C:\Windows\System32\cmd.exe`,
			expected: false,
		},
		{
			name:     "not in bin",
			path:     filepath.Join(tempDir, "random.exe"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isStandaloneWindowsInstall(tt.path)
			if result != tt.expected {
				t.Errorf("isStandaloneWindowsInstall(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

// TestResolveBinaryPath tests .exe auto-detection
func TestResolveBinaryPath(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	// Create a test binary with .exe extension
	tempDir := t.TempDir()
	testExe := filepath.Join(tempDir, "testapp.exe")
	if err := os.WriteFile(testExe, []byte{}, 0755); err != nil {
		t.Fatal(err)
	}

	// Add temp dir to PATH for this test
	oldPath := os.Getenv("PATH")
	defer os.Setenv("PATH", oldPath)
	os.Setenv("PATH", tempDir+";"+oldPath)

	tests := []struct {
		name        string
		input       string
		shouldFind  bool
		shouldHave  string
	}{
		{
			name:       "with .exe extension",
			input:      "testapp.exe",
			shouldFind: true,
			shouldHave: ".exe",
		},
		{
			name:       "without .exe extension",
			input:      "testapp",
			shouldFind: true,
			shouldHave: ".exe",
		},
		{
			name:       "nonexistent binary",
			input:      "doesnotexist",
			shouldFind: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := resolveBinaryPath(tt.input)
			
			if tt.shouldFind {
				if err != nil {
					t.Errorf("resolveBinaryPath(%q) unexpected error: %v", tt.input, err)
				}
				if tt.shouldHave != "" && !strings.HasSuffix(result, tt.shouldHave) {
					t.Errorf("resolveBinaryPath(%q) = %q, expected to end with %q", tt.input, result, tt.shouldHave)
				}
			} else {
				if err == nil {
					t.Errorf("resolveBinaryPath(%q) should have failed but got: %q", tt.input, result)
				}
			}
		})
	}
}

// TestPlanStandaloneWindowsInstallFiles tests support file packaging
func TestPlanStandaloneWindowsInstallFiles(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	// Create a complete install structure
	tempDir := t.TempDir()
	installRoot := filepath.Join(tempDir, "test-install")
	
	// Create directory structure
	dirs := []string{
		filepath.Join(installRoot, "bin"),
		filepath.Join(installRoot, "share", "config"),
		filepath.Join(installRoot, "lib"),
		filepath.Join(installRoot, "etc"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}

	// Create some files
	files := map[string]string{
		filepath.Join(installRoot, "bin", "app.exe"):            "binary",
		filepath.Join(installRoot, "bin", "helper.dll"):         "dll",
		filepath.Join(installRoot, "share", "config", "app.cfg"): "config",
		filepath.Join(installRoot, "lib", "libtest.a"):          "static lib",
		filepath.Join(installRoot, "etc", "settings.conf"):      "settings",
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	testExe := filepath.Join(installRoot, "bin", "app.exe")

	// Plan operations
	ops, err := planStandaloneWindowsInstallFiles(testExe, nil)
	if err != nil {
		t.Fatalf("planStandaloneWindowsInstallFiles failed: %v", err)
	}

	// Verify operations
	if len(ops) == 0 {
		t.Fatal("Expected some file operations")
	}

	// Check that bin/ files are NOT included (handled separately)
	for _, op := range ops {
		relPath, _ := filepath.Rel(installRoot, op.Source)
		if strings.HasPrefix(relPath, "bin") {
			t.Errorf("bin/ files should not be included, found: %s", relPath)
		}
	}

	// Check that share/, lib/, etc/ files ARE included
	foundShare := false
	foundLib := false
	foundEtc := false
	for _, op := range ops {
		relPath, _ := filepath.Rel(installRoot, op.Source)
		if strings.HasPrefix(relPath, "share") {
			foundShare = true
		}
		if strings.HasPrefix(relPath, "lib") {
			foundLib = true
		}
		if strings.HasPrefix(relPath, "etc") {
			foundEtc = true
		}
	}

	if !foundShare {
		t.Error("Expected share/ files to be included")
	}
	if !foundLib {
		t.Error("Expected lib/ files to be included")
	}
	if !foundEtc {
		t.Error("Expected etc/ files to be included")
	}
}

// TestPlanStandaloneWindowsInstallFiles_WithIgnore tests .bundleignore filtering
func TestPlanStandaloneWindowsInstallFiles_WithIgnore(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	// Create install structure with files we want to ignore
	tempDir := t.TempDir()
	installRoot := filepath.Join(tempDir, "test-install")
	
	dirs := []string{
		filepath.Join(installRoot, "bin"),
		filepath.Join(installRoot, "share", "doc"),
		filepath.Join(installRoot, "lib"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}

	files := map[string]string{
		filepath.Join(installRoot, "bin", "app.exe"):         "binary",
		filepath.Join(installRoot, "share", "doc", "README.md"): "docs",
		filepath.Join(installRoot, "lib", "test.lib"):        "static lib",
		filepath.Join(installRoot, "lib", "test.dll"):        "dynamic lib",
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	testExe := filepath.Join(installRoot, "bin", "app.exe")
	ignorePatterns := []string{
		"share/doc/*",
		"*.lib",
	}

	// Plan operations with ignore patterns
	ops, err := planStandaloneWindowsInstallFiles(testExe, ignorePatterns)
	if err != nil {
		t.Fatalf("planStandaloneWindowsInstallFiles failed: %v", err)
	}

	// Verify ignored files are not included
	for _, op := range ops {
		relPath, _ := filepath.Rel(installRoot, op.Source)
		
		if strings.Contains(relPath, filepath.Join("share", "doc")) {
			t.Errorf("share/doc/* should be ignored, found: %s", relPath)
		}
		if strings.HasSuffix(relPath, ".lib") {
			t.Errorf("*.lib files should be ignored, found: %s", relPath)
		}
	}

	// Verify .dll file IS included (not ignored)
	foundDLL := false
	for _, op := range ops {
		if strings.HasSuffix(op.Source, "test.dll") {
			foundDLL = true
			break
		}
	}
	if !foundDLL {
		t.Error("Expected test.dll to be included (not ignored)")
	}
}
