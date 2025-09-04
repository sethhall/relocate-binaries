package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	binaries         []string
	helpFlag         bool
	verboseFlag      bool
	archiveFlag      bool
	outputDir        string
	finalInstallPath string
	forceFlag        bool
	dryRunFlag       bool
	bundleIgnoreFile string
	externalTools    = map[string][]string{
		"darwin": {"otool", "install_name_tool"},
		"linux":  {"ldd", "patchelf", "file"},
	}
)

//go:embed wrapper/wrapper.c
var wrapperSource embed.FS

type FileOperation struct {
	Source      string      `json:"source"`
	Destination string      `json:"destination"`
	IsSymlink   bool        `json:"is_symlink"`
	LinkTarget  string      `json:"link_target,omitempty"`
	IsDirectory bool        `json:"is_directory"`
	Permissions os.FileMode `json:"permissions"`
}

func init() {
	flag.Func("p", "Specify a binary to package (can be used multiple times)", func(s string) error {
		binaries = append(binaries, s)
		return nil
	})
	flag.BoolVar(&helpFlag, "help", false, "Display help information")
	flag.BoolVar(&verboseFlag, "v", false, "Enable verbose output")
	flag.BoolVar(&archiveFlag, "archive", false, "Create a compressed archive of the final bundle")
	flag.BoolVar(&forceFlag, "f", false, "Force the tool to proceed even if the output directory exists")
	flag.BoolVar(&dryRunFlag, "dry-run", false, "Enable dry-run mode")
	flag.StringVar(&outputDir, "output", "output", "Specify the output directory")
	flag.StringVar(&finalInstallPath, "install-path", "", "Specify the final installation path for the package")
	flag.StringVar(&bundleIgnoreFile, "ignore-file", "", "Specify the path to the bundle ignore file")
	flag.Usage = usage
}

func usage() {
	fmt.Fprintf(os.Stderr, `Sensor Setup Tool

This program packages specified binaries along with their dependencies into a 'sensor' directory.

It copies the binaries, their shared libraries, and sets up the correct RPATH.

Usage:

  %s -p <binary1> [-p <binary2> ...] [-v] [-archive] [-output <directory>] [-install-path <path>] [-f] [--dry-run]

Flags:

`, os.Args[0])
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `

Examples:

  %s -p zeek -p suricata
  %s -p /nix/store/*/bin/zeek -p /nix/store/*/bin/suricata -v -archive -output custom_sensor -install-path /opt/sensor

The program will create a 'sensor' directory (or the specified output directory) with the following structure:

  sensor/
    ├── bin/
    │   ├── binary1
    │   └── binary2
    └── lib/
        └── (shared libraries)

If --install-path is specified, the binaries will be configured to work when installed at that location.

Note: This program may need to be run with elevated privileges to access certain system libraries.

`, os.Args[0], os.Args[0])
}

func main() {
	flag.Parse()

	if helpFlag {
		flag.Usage()
		return
	}

	if len(binaries) == 0 {
		fmt.Println("Error: No binaries specified. Use -p flag to specify binaries.")
		flag.Usage()
		os.Exit(1)
	}

	if verboseFlag {
		fmt.Println("Verbose mode enabled")
	}

	if finalInstallPath == "" {
		fmt.Println("Warning: No final installation path specified. The package may not be fully standalone.")
	} else {
		fmt.Printf("Final installation path set to: %s\n", finalInstallPath)
	}

	// Check for external tools
	if err := checkExternalTools(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	var err error
	outputDir, err = filepath.Abs(outputDir)
	if err != nil {
		fmt.Printf("Error getting absolute path for sensor directory: %v\n", err)
		return
	}

	// Check if output directory exists
	if _, err := os.Stat(outputDir); !os.IsNotExist(err) {
		if !forceFlag {
			fmt.Printf("Error: Output directory %s already exists. Use -f flag to force the tool to proceed.\n", outputDir)
			os.Exit(1)
		} else if verboseFlag {
			fmt.Printf("Output directory %s already exists, but proceeding due to -f flag.\n", outputDir)
		}
	}

	// NOTE: Do not create directories or build artifacts before checking --dry-run.

	var ignorePatterns []string

	if bundleIgnoreFile != "" {
		ignorePatterns, err = readIgnoreFile(bundleIgnoreFile)
		if err != nil {
			fmt.Printf("Error reading ignore file: %v\n", err)
			// Continue without ignore patterns if there's an error
		}
	}

	// Planning stage: Build the list of FileOperation structs
	var allFileOperations []FileOperation
	for _, binary := range binaries {
		ops, err := planFileOperations(binary, ignorePatterns)
		if err != nil {
			fmt.Printf("Error planning file operations for binary %s: %v\n", binary, err)
			if strings.Contains(err.Error(), "missing libraries") {
				fmt.Println("Failure due to missing libraries!")
				os.Exit(1)
			}
		}
		allFileOperations = append(allFileOperations, ops...)
	}

	// Filter out ignored files
	fileOperations := filterIgnoredFiles(allFileOperations, ignorePatterns)

	// Dry-run mode: Print the planned operations and exit
	if dryRunFlag {
		fmt.Println("Dry-run mode enabled. Planned file operations:")
		for _, op := range fileOperations {
			fmt.Printf("Source: %s, Destination: %s, IsSymlink: %t, LinkTarget: %s\n", op.Source, op.Destination, op.IsSymlink, op.LinkTarget)
		}
		return
	}

	// Create directories now that we're committed to executing (not a dry run)
	err = os.MkdirAll(filepath.Join(outputDir, "bin"), 0755)
	if err != nil {
		fmt.Printf("Error creating sensor/bin directory: %v\n", err)
		return
	}
	err = os.MkdirAll(filepath.Join(outputDir, "lib"), 0755)
	if err != nil {
		fmt.Printf("Error creating sensor/lib directory: %v\n", err)
		return
	}

	// Build and install the wrapper tool on Linux
	if runtime.GOOS == "linux" {
		err := buildAndInstallWrapper()
		if err != nil {
			fmt.Printf("Error building and installing wrapper: %v\n", err)
			return
		}
	}

	// Write the manifest
	if err := writeManifest(fileOperations); err != nil {
		fmt.Printf("Error writing manifest: %v\n", err)
		return
	}

	// Execute file operations
	err = executeFileOperations(fileOperations)
	if err != nil {
		fmt.Printf("Errors occurred during file operations: %v\n", err)
		// Decide whether to exit here or continue with the rest of the process
		os.Exit(1)
	}

	// Create symlinks for the executables on linux
	if runtime.GOOS == "linux" {
		err = createSymlinks()
		if err != nil {
			fmt.Printf("Error creating symlinks and copying wrapper: %v\n", err)
			// Decide whether to exit here or continue with the rest of the process
			os.Exit(1)
		}
	}

	// Update RPATH and relocate libraries
	for _, dir := range []string{"bin", "lib"} {
		err = filepath.Walk(filepath.Join(outputDir, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				if runtime.GOOS == "darwin" {
					err = processLibrariesMacOS(path)
					if err != nil {
						fmt.Printf("Warning: %v\n", err)
					}
				} else {
					// Exclude setting RPATH for the wrapper tool
					if filepath.Base(path) != "wrapper" {
						err = addRPATHLinux(path)
						if err != nil {
							fmt.Printf("Warning: %v\n", err)
						}
					}
				}
				if verboseFlag {
					fmt.Printf("Processed RPATH and libraries for: %s\n", path)
				}
			}
			return nil
		})
		if err != nil {
			fmt.Printf("Error updating RPATH and relocating libraries: %v\n", err)
		}
	}

	// Apply final permissions
	err = applyFinalPermissions(fileOperations)
	if err != nil {
		fmt.Printf("Errors occurred while applying final permissions: %v\n", err)
		// Decide whether to exit here or continue with the rest of the process
		os.Exit(1)
	}

	// Code sign binaries and libraries on macOS after modifications
	if runtime.GOOS == "darwin" {
		if verboseFlag {
			fmt.Println("Code signing binaries and libraries...")
		}
		for _, dir := range []string{"bin", "lib"} {
			err = filepath.Walk(filepath.Join(outputDir, dir), func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() {
					err = codeSignBinary(path)
					if err != nil {
						fmt.Printf("Warning: Failed to code sign %s: %v\n", path, err)
					}
				}
				return nil
			})
			if err != nil {
				fmt.Printf("Error during code signing: %v\n", err)
			}
		}
	}

	if archiveFlag {
		err := createArchive()
		if err != nil {
			fmt.Printf("Error creating archive: %v\n", err)
		} else {
			fmt.Println("Archive created successfully.")
		}
	}

	fmt.Println("All operations completed.")
}

func checkExternalTools() error {
	tools, ok := externalTools[runtime.GOOS]
	if !ok {
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	for _, tool := range tools {
		path, err := exec.LookPath(tool)
		if err != nil {
			return fmt.Errorf("required tool '%s' not found in PATH", tool)
		}
		if verboseFlag {
			fmt.Printf("Found %s at: %s\n", tool, path)
		}
	}

	return nil
}

func readIgnoreFile(ignoreFilePath string) ([]string, error) {
	file, err := os.Open(ignoreFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No ignore file found, return empty list
		}
		return nil, err
	}
	defer file.Close()

	var patterns []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		pattern := strings.TrimSpace(scanner.Text())
		if pattern != "" && !strings.HasPrefix(pattern, "#") {
			patterns = append(patterns, pattern)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return patterns, nil
}

func shouldIgnore(path string, ignorePatterns []string) bool {
	// Normalize the path to use forward slashes
	normalizedPath := filepath.ToSlash(path)

	for _, pattern := range ignorePatterns {
		// Normalize the pattern to use forward slashes
		normalizedPattern := filepath.ToSlash(pattern)

		// Check if the pattern matches from the left
		if strings.HasPrefix(normalizedPath, normalizedPattern) {
			// If the pattern exactly matches the path, or the next character is a slash
			// (indicating the pattern matches a directory), we should ignore this path
			if len(normalizedPath) == len(normalizedPattern) ||
				(len(normalizedPath) > len(normalizedPattern) && normalizedPath[len(normalizedPattern)] == '/') {
				return true
			}
		}

		// Handle wildcard patterns
		if strings.Contains(normalizedPattern, "*") {
			if matchWildcard(normalizedPath, normalizedPattern) {
				return true
			}
		}
	}
	return false
}

func matchWildcard(path, pattern string) bool {
	parts := strings.Split(pattern, "/")
	pathParts := strings.Split(path, "/")

	for i, part := range parts {
		if i >= len(pathParts) {
			// If we've reached the end of the path but not the pattern,
			// it's only a match if the rest of the pattern parts are all "*"
			for _, remainingPart := range parts[i:] {
				if remainingPart != "*" {
					return false
				}
			}
			return true
		}

		if part == "*" {
			continue
		}

		matched, err := filepath.Match(part, pathParts[i])
		if err != nil || !matched {
			return false
		}
	}

	// If we've matched all parts of the pattern but there's still more to the path,
	// it's a match (because we're matching from the left)
	return true
}

func filterIgnoredFiles(ops []FileOperation, ignorePatterns []string) []FileOperation {
	var filteredOps []FileOperation
	for _, op := range ops {
		relPath, err := filepath.Rel(outputDir, op.Destination)
		if err == nil && !shouldIgnore(relPath, ignorePatterns) {
			filteredOps = append(filteredOps, op)
		}
	}
	return filteredOps
}

func planFileOperations(binary string, ignorePatterns []string) ([]FileOperation, error) {
	var fileOperations []FileOperation

	binaryPath, err := exec.LookPath(binary)
	if err != nil {
		return nil, fmt.Errorf("error finding %s: %v", binary, err)
	}

	binaryPath, err = filepath.Abs(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("error getting absolute path for %s: %v", binary, err)
	}

	destPath := filepath.Join(outputDir, "bin", filepath.Base(binaryPath))
	if runtime.GOOS == "linux" {
		destPath = filepath.Join(outputDir, "bin", "."+filepath.Base(binaryPath))
	}

	fileInfo, err := os.Lstat(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("error getting file info for %s: %v", binary, err)
	}

	if !shouldIgnore(binaryPath, ignorePatterns) {
		fileOperations = append(fileOperations, FileOperation{
			Source:      binaryPath,
			Destination: destPath,
			IsSymlink:   false,
			IsDirectory: false,
			Permissions: fileInfo.Mode().Perm(),
		})
	}

	// Plan shared libraries copy operations
	ops, err := planSharedLibraries(binaryPath, ignorePatterns)
	if err != nil {
		return nil, fmt.Errorf("error planning shared libraries for %s: %v", binary, err)
	}

	fileOperations = append(fileOperations, ops...)

	// Handle nix packages
	if isNixPkg(binaryPath) {
		if verboseFlag {
			fmt.Printf("Detected nix package: %s\n", binaryPath)
		}
		ops, err := planNixPkgFiles(binaryPath, ignorePatterns)
		if err != nil {
			return nil, fmt.Errorf("error planning nix package files for %s: %v", binary, err)
		}
		fileOperations = append(fileOperations, ops...)
	}

	// Handle homebrew packages
	if isHomebrewPkg(binaryPath) {
		if verboseFlag {
			fmt.Printf("Detected homebrew package: %s\n", binaryPath)
		}
		ops, err := planHomebrewPkgFiles(binaryPath, ignorePatterns)
		if err != nil {
			return nil, fmt.Errorf("error planning homebrew package files for %s: %v", binary, err)
		}
		fileOperations = append(fileOperations, ops...)
	}

	return fileOperations, nil
}

func createSymlinks() error {
	if runtime.GOOS != "linux" {
		return nil
	}

	binDir := filepath.Join(outputDir, "bin")
	files, err := os.ReadDir(binDir)
	if err != nil {
		return fmt.Errorf("error reading bin directory: %v", err)
	}

	// Create symlinks
	for _, file := range files {
		if !file.IsDir() && strings.HasPrefix(file.Name(), ".") && file.Name() != ".wrapper" {
			execName := strings.TrimPrefix(file.Name(), ".")
			symlinkPath := filepath.Join(binDir, execName)
			if err := os.Symlink("./wrapper", symlinkPath); err != nil {
				fmt.Printf("Warning: Error creating symlink for %s: %v\n", execName, err)
			} else if verboseFlag {
				fmt.Printf("Created symlink: %s -> ./wrapper\n", symlinkPath)
			}
		}
	}

	return nil
}

func planSharedLibraries(binaryPath string, ignorePatterns []string) ([]FileOperation, error) {
	if verboseFlag {
		fmt.Printf("Planning shared libraries for: %s\n", binaryPath)
	}

	var output []byte
	var err error

	if runtime.GOOS == "darwin" {
		output, err = exec.Command("otool", "-L", binaryPath).Output()
	} else {
		output, err = exec.Command("ldd", binaryPath).Output()
	}

	if err != nil {
		return nil, fmt.Errorf("error listing shared libraries: %v", err)
	}

	lines := strings.Split(string(output), "\n")

	if runtime.GOOS == "darwin" {
		return planSharedLibrariesMacOS(lines, binaryPath, ignorePatterns, outputDir)
	} else {
		return planSharedLibrariesLinux(lines, binaryPath, ignorePatterns, outputDir)
	}
}

func planSharedLibrariesMacOS(lines []string, binaryPath string, ignorePatterns []string, outputDir string) ([]FileOperation, error) {
	var fileOperations []FileOperation
	seenDestinations := make(map[string]bool)

	// Get RPATH entries for resolving @rpath references
	rpaths, err := getRPATHs(binaryPath)
	if err != nil {
		if verboseFlag {
			fmt.Printf("Warning: Could not get RPATH entries for %s: %v\n", binaryPath, err)
		}
		// Continue without RPATH resolution
		rpaths = []string{}
	}

	for i, line := range lines {
		if i == 0 || len(strings.TrimSpace(line)) == 0 {
			continue // Skip the first line (binary path) and empty lines
		}

		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) >= 1 {
			libPath := parts[0]
			
			// Resolve @rpath references
			if strings.HasPrefix(libPath, "@rpath/") {
				resolvedPath := resolveRPATH(libPath, rpaths)
				if resolvedPath == "" {
					if verboseFlag {
						fmt.Printf("Warning: Could not resolve %s using RPATH entries: %v\n", libPath, rpaths)
					}
					continue // Skip this library if we can't resolve it
				}
				libPath = resolvedPath
			}
			
			if !isSystemLibrary(libPath) && !shouldIgnore(libPath, ignorePatterns) {
				destPath := filepath.Join(outputDir, "lib", filepath.Base(libPath))
				fileOps, err := createFileOperation(libPath, destPath, outputDir)
				if err != nil {
					return nil, err
				}
				for _, op := range fileOps {
					if !seenDestinations[op.Destination] {
						fileOperations = append(fileOperations, op)
						seenDestinations[op.Destination] = true
					}
				}
			}
		}
	}

	return fileOperations, nil
}

func planSharedLibrariesLinux(lines []string, binaryPath string, ignorePatterns []string, outputDir string) ([]FileOperation, error) {
	var fileOperations []FileOperation
	seenDestinations := make(map[string]bool)
	var missingLibraries []string

	for _, line := range lines {
		if strings.Contains(line, "=>") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				if parts[2] == "not" {
					missingLibraries = append(missingLibraries, parts[0])
					continue
				}
				libPath := parts[2]
				if !isSystemLibrary(libPath) && !shouldIgnore(libPath, ignorePatterns) {
					destPath := filepath.Join(outputDir, "lib", filepath.Base(libPath))
					if err := addFileOperation(libPath, destPath, &fileOperations, seenDestinations); err != nil {
						return nil, err
					}
				}
			}
		} else if strings.Contains(line, "ld-linux-") {
			libPath := strings.Fields(line)[0]
			if !shouldIgnore(libPath, ignorePatterns) {
				destPath := filepath.Join(outputDir, "lib", filepath.Base(libPath))
				if err := addFileOperation(libPath, destPath, &fileOperations, seenDestinations); err != nil {
					return nil, err
				}
			}
		}
	}

	if len(missingLibraries) > 0 {
		return nil, fmt.Errorf("missing libraries: %v", missingLibraries)
	}

	return fileOperations, nil
}

func addFileOperation(source, dest string, operations *[]FileOperation, seen map[string]bool) error {
	if seen[dest] {
		return nil
	}

	info, err := os.Stat(source)
	if err != nil {
		return err
	}

	op := FileOperation{
		Source:      source,
		Destination: dest,
		IsSymlink:   false,
		IsDirectory: info.IsDir(),
		Permissions: info.Mode().Perm(),
	}

	*operations = append(*operations, op)
	seen[dest] = true

	return nil
}

func createFileOperation(sourcePath, destPath string, baseDir string) ([]FileOperation, error) {
	log.Printf("DEBUG: Starting createFileOperation for sourcePath: %s, destPath: %s, baseDir: %s", sourcePath, destPath, baseDir)

	fileInfo, err := os.Lstat(sourcePath)
	if err != nil {
		log.Printf("ERROR: Failed to get file info for %s: %v", sourcePath, err)
		return nil, fmt.Errorf("error getting file info for %s: %v", sourcePath, err)
	}

	log.Printf("DEBUG: File info obtained for %s", sourcePath)

	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		log.Printf("ERROR: Failed to get absolute path for baseDir %s: %v", baseDir, err)
		return nil, fmt.Errorf("can't make the baseDir(%s) absolute: %s", baseDir, err)
	}

	log.Printf("DEBUG: Absolute baseDir: %s", absBaseDir)

	if fileInfo.Mode()&os.ModeSymlink != 0 {
		log.Printf("DEBUG: File is a symlink")
		linkTarget, err := os.Readlink(sourcePath)
		if err != nil {
			log.Printf("ERROR: Failed to read symlink %s: %v", sourcePath, err)
			return nil, fmt.Errorf("error reading symlink %s: %v", sourcePath, err)
		}

		log.Printf("DEBUG: Symlink target: %s", linkTarget)

		// Resolve the absolute path of the link target
		absLinkTarget := linkTarget
		if !filepath.IsAbs(linkTarget) {
			absLinkTarget = filepath.Join(filepath.Dir(sourcePath), linkTarget)
		}

		// Check if the link target exists
		targetInfo, err := os.Stat(absLinkTarget)
		if err != nil {
			log.Printf("ERROR: Failed to get info for symlink target %s: %v", absLinkTarget, err)
			return nil, fmt.Errorf("error getting info for symlink target %s: %v", absLinkTarget, err)
		}

		// Create a FileOperation for the actual file, not the symlink
		fileOp := FileOperation{
			Source:      absLinkTarget,
			Destination: destPath,
			IsSymlink:   false,
			IsDirectory: targetInfo.IsDir(),
			Permissions: targetInfo.Mode().Perm(),
		}

		log.Printf("DEBUG: Created FileOperation for symlink target: %+v", fileOp)
		return []FileOperation{fileOp}, nil
	}

	// If it's not a symlink, proceed as before
	fileOp := FileOperation{
		Source:      sourcePath,
		Destination: destPath,
		IsSymlink:   false,
		IsDirectory: fileInfo.IsDir(),
		Permissions: fileInfo.Mode().Perm(),
	}

	log.Printf("DEBUG: Returning FileOperation: %+v", fileOp)
	return []FileOperation{fileOp}, nil
}

func getRPATHs(binaryPath string) ([]string, error) {
	output, err := exec.Command("otool", "-l", binaryPath).Output()
	if err != nil {
		return nil, fmt.Errorf("error running otool -l: %v", err)
	}

	var rpaths []string
	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if strings.Contains(line, "LC_RPATH") {
			// Look for the path line which should be a few lines after LC_RPATH
			for j := i + 1; j < len(lines) && j < i+5; j++ {
				if strings.Contains(lines[j], "path ") {
					// Extract the path from a line like "         path /opt/homebrew/lib (offset 12)"
					parts := strings.Fields(lines[j])
					for k, part := range parts {
						if part == "path" && k+1 < len(parts) {
							rpath := parts[k+1]
							rpaths = append(rpaths, rpath)
							break
						}
					}
					break
				}
			}
		}
	}

	return rpaths, nil
}

func resolveRPATH(libPath string, rpaths []string) string {
	if !strings.HasPrefix(libPath, "@rpath/") {
		return libPath // Not an @rpath reference
	}

	// Remove @rpath/ prefix
	relativePath := strings.TrimPrefix(libPath, "@rpath/")

	// Try each RPATH entry
	for _, rpath := range rpaths {
		fullPath := filepath.Join(rpath, relativePath)
		if _, err := os.Stat(fullPath); err == nil {
			return fullPath
		}
	}

	return "" // Could not resolve
}

func isSystemLibrary(path string) bool {
	systemPaths := []string{
		"/usr/lib",
		"/System/Library",
		"/Library/Apple",
		"/System/iOSSupport",
		"/Library/Developer",
	}
	for _, sysPath := range systemPaths {
		if strings.HasPrefix(path, sysPath) {
			return true
		}
	}
	return false
}

func updateLibraryIdentity(libPath string) error {
	// Get the current library identity
	output, err := exec.Command("otool", "-D", libPath).Output()
	if err != nil {
		return fmt.Errorf("error getting library identity: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		return fmt.Errorf("unexpected otool -D output")
	}

	currentID := strings.TrimSpace(lines[1])
	libraryName := filepath.Base(libPath)
	newID := "@rpath/" + libraryName

	// Only update if the current ID is not already using @rpath
	if currentID != newID && !strings.HasPrefix(currentID, "@rpath/") {
		cmd := exec.Command("install_name_tool", "-id", newID, libPath)
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("failed to update library identity: %v", err)
		}
		if verboseFlag {
			fmt.Printf("Updated library identity from %s to %s in %s\n", currentID, newID, libPath)
		}
	}

	return nil
}

func codeSignBinary(path string) error {
	// Re-sign the binary to fix code signature after modifications
	cmd := exec.Command("codesign", "--force", "--sign", "-", path)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to code sign %s: %v", path, err)
	}
	if verboseFlag {
		fmt.Printf("Code signed: %s\n", path)
	}
	return nil
}

func executeFileOperations(fileOperations []FileOperation) error {
	var errors []string
	for _, op := range fileOperations {
		var err error
		if op.IsSymlink {
			err = createSymlink(op)
		} else if op.IsDirectory {
			err = os.MkdirAll(op.Destination, 0777)
		} else {
			err = copyFileWithIO(op.Source, op.Destination)
		}
		if err != nil {
			errors = append(errors, fmt.Sprintf("Error processing %s: %v", op.Source, err))
			fmt.Printf("Warning: %s\n", errors[len(errors)-1])
		}
	}

	// Only rename and create symlinks for the wrapper on Linux
	if runtime.GOOS == "linux" {
		binDir := filepath.Join(outputDir, "bin")
		files, err := os.ReadDir(binDir)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Error reading bin directory: %v", err))
		} else {
			for _, file := range files {
				if !file.IsDir() && !strings.HasPrefix(file.Name(), ".") {
					err := renameAndCreateSymlink(filepath.Join(binDir, file.Name()))
					if err != nil {
						errors = append(errors, fmt.Sprintf("Error renaming and creating symlink: %v", err))
					}
				}
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("encountered %d errors during file operations:\n%s", len(errors), strings.Join(errors, "\n"))
	}
	return nil
}

func writeManifest(fileOperations []FileOperation) error {
	manifestPath := filepath.Join(outputDir, "manifest.json")
	file, err := os.Create(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to create manifest file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // Pretty print the JSON
	if err := encoder.Encode(fileOperations); err != nil {
		return fmt.Errorf("failed to encode manifest: %v", err)
	}

	if verboseFlag {
		fmt.Printf("Manifest file created: %s\n", manifestPath)
	}

	return nil
}

func createSymlink(op FileOperation) error {
	if err := os.MkdirAll(filepath.Dir(op.Destination), 0755); err != nil {
		return fmt.Errorf("error creating parent directory for symlink: %v", err)
	}

	// Read the original symlink
	originalTarget, err := os.Readlink(op.Source)
	if err != nil {
		return fmt.Errorf("error reading original symlink %s: %v", op.Source, err)
	}

	// Determine if the symlink is absolute or relative
	var linkTarget string
	if filepath.IsAbs(originalTarget) {
		// If it's an absolute path, we need to adjust it to the new location
		relPath, err := filepath.Rel(filepath.Dir(op.Source), originalTarget)
		if err != nil {
			return fmt.Errorf("error calculating relative path: %v", err)
		}
		linkTarget = filepath.Join(filepath.Dir(op.Destination), relPath)
	} else {
		// If it's a relative path, we can use it as is
		linkTarget = originalTarget
	}

	// Ensure that no symlink points at itself
	if linkTarget == op.Destination {
		return fmt.Errorf("symlink %s points at itself", op.Destination)
	}

	// Remove the destination if it already exists
	if err := os.RemoveAll(op.Destination); err != nil {
		return fmt.Errorf("error removing existing destination: %v", err)
	}

	// Create the new symlink
	if err := os.Symlink(linkTarget, op.Destination); err != nil {
		return fmt.Errorf("error creating symlink: %v", err)
	}

	if verboseFlag {
		fmt.Printf("Successfully created symlink: %s -> %s\n", op.Destination, linkTarget)
	}

	return nil
}

func copyFileOrDir(op FileOperation) error {
	sourceInfo, err := os.Stat(op.Source)
	if err != nil {
		return fmt.Errorf("error getting source info: %v", err)
	}

	if sourceInfo.IsDir() {
		return copyDir(op.Source, op.Destination)
	}
	return copyFile(op.Source, op.Destination)
}

func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return fmt.Errorf("error creating directory: %v", err)
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("error reading directory: %v", err)
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				fmt.Printf("Warning: Failed to copy directory %s to %s: %v\n", srcPath, dstPath, err)
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				fmt.Printf("Warning: Failed to copy file %s to %s: %v\n", srcPath, dstPath, err)
			}
		}
	}

	return nil
}

func copyFile(src, dst string) error {
	if _, err := os.Stat(dst); err == nil {
		if verboseFlag {
			fmt.Printf("File already exists, skipping: %s\n", dst)
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("error creating parent directory: %v", err)
	}

	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("error opening source file: %v", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("error creating destination file: %v", err)
	}
	defer destFile.Close()

	if _, err = io.Copy(destFile, sourceFile); err != nil {
		return fmt.Errorf("error copying file contents: %v", err)
	}

	sourceInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("error getting source file info: %v", err)
	}

	if err = os.Chmod(dst, sourceInfo.Mode()); err != nil {
		return fmt.Errorf("error setting file permissions: %v", err)
	}

	if verboseFlag {
		fmt.Printf("Successfully copied: %s to %s\n", src, dst)
	}

	return nil
}

func copyFileWithIO(src, dst string) error {
	if verboseFlag {
		fmt.Printf("Attempting to copy: %s to %s\n", src, dst)
	}
	// Ensure the destination directory exists
	dstDir := filepath.Dir(dst)
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return fmt.Errorf("error creating destination directory %s: %v", dstDir, err)
	}
	// Check if destination file already exists
	if _, err := os.Stat(dst); err == nil {
		if verboseFlag {
			fmt.Printf("File already exists, removing: %s\n", dst)
		}
		if err := os.Remove(dst); err != nil {
			return fmt.Errorf("error removing existing file %s: %v", dst, err)
		}
	}
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("error opening source file %s: %v", src, err)
	}
	defer sourceFile.Close()
	destFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		return fmt.Errorf("error creating destination file %s: %v", dst, err)
	}
	defer destFile.Close()
	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return fmt.Errorf("error copying file contents from %s to %s: %v", src, dst, err)
	}
	if verboseFlag {
		fmt.Printf("Successfully copied: %s to %s\n", src, dst)
	}
	return nil
}

func addRPATHLinux(path string) error {
	// Check if the file is an ELF binary or shared library
	cmd := exec.Command("file", path)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("error checking file type for %s: %v", path, err)
	}
	if !strings.Contains(string(output), "ELF") {
		if verboseFlag {
			fmt.Printf("Skipping non-ELF file: %s\n", path)
		}
		return nil
	}

	// Ensure the file is writable
	err = os.Chmod(path, 0755)
	if err != nil {
		return fmt.Errorf("error setting file permissions for %s: %v", path, err)
	}

	// Update the interpreter path only for executables
	if strings.Contains(string(output), "executable") {
		err = updateInterpreterPath(path)
		if err != nil {
			return fmt.Errorf("failed to update interpreter path for %s: %v", path, err)
		}
	}

	// Set relative RPATH
	// Get the base name of the file
	baseName := filepath.Base(path)
	// Check if the file is an ld-linux library (we don't want to mess with rpath in that case)
	if !strings.HasPrefix(baseName, "ld-linux") {
		newRpath := "$ORIGIN/../lib"
		cmd = exec.Command("patchelf", "--set-rpath", newRpath, path)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to set RPATH for %s: %v\nOutput: %s", path, err, string(output))
		}
		if verboseFlag {
			fmt.Printf("Set RPATH to %s for: %s\n", newRpath, path)
		}

	}

	return nil
}

func updateInterpreterPath(path string) error {
	if finalInstallPath == "" {
		return nil // No need to update if final install path is not specified
	}

	// Find the ld-linux.so in our lib directory
	ldLinuxPath := ""
	err := filepath.Walk(filepath.Join(outputDir, "lib"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(filepath.Base(path), "ld-linux") {
			ldLinuxPath = path
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("error finding ld-linux.so: %v", err)
	}
	if ldLinuxPath == "" {
		return fmt.Errorf("ld-linux.so not found in lib directory")
	}

	// Calculate the final path of ld-linux.so
	finalLdLinuxPath := filepath.Join(finalInstallPath, "lib", filepath.Base(ldLinuxPath))

	// Update the interpreter path
	cmd := exec.Command("patchelf", "--set-interpreter", finalLdLinuxPath, path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set interpreter for %s: %v\nOutput: %s", path, err, string(output))
	}

	if verboseFlag {
		fmt.Printf("Updated interpreter path to %s for: %s\n", finalLdLinuxPath, path)
	}

	return nil
}

func addRPATHMacOS(path string) error {
	// Check if the file is a Mach-O binary or dynamic library
	cmd := exec.Command("file", path)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("error checking file type for %s: %v", path, err)
	}
	if !strings.Contains(string(output), "Mach-O") {
		if verboseFlag {
			fmt.Printf("Skipping non-Mach-O file: %s\n", path)
		}
		return nil
	}

	// Add @executable_path/../lib RPATH
	cmd = exec.Command("install_name_tool", "-add_rpath", "@executable_path/../lib", path)
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to add @executable_path/../lib RPATH for %s: %v", path, err)
	}

	// Add @loader_path/../lib RPATH
	cmd = exec.Command("install_name_tool", "-add_rpath", "@loader_path/../lib", path)
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to add @loader_path/../lib RPATH for %s: %v", path, err)
	}

	if verboseFlag {
		fmt.Printf("Added RPATHs to: %s\n", path)
	}

	return nil
}

func updateMacOSLibPaths(binaryPath string) error {
	output, err := exec.Command("otool", "-L", binaryPath).Output()
	if err != nil {
		return fmt.Errorf("error listing shared libraries: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i == 0 { // Skip the first line as it's the binary itself
			continue
		}
		if strings.Contains(line, "/") {
			parts := strings.Fields(strings.TrimSpace(line))
			if len(parts) > 0 {
				libPath := parts[0]
				if !isSystemLibrary(libPath) {
					newPath := "@rpath/" + filepath.Base(libPath)
					cmd := exec.Command("install_name_tool", "-change", libPath, newPath, binaryPath)
					err = cmd.Run()
					if err != nil {
						fmt.Printf("Warning: Failed to update library path %s to %s in %s: %v\n", libPath, newPath, binaryPath, err)
					} else if verboseFlag {
						fmt.Printf("Updated library path: %s to %s in %s\n", libPath, newPath, binaryPath)
					}

					// Copy the library if it's not already in the lib directory
					destPath := filepath.Join(outputDir, "lib", filepath.Base(libPath))
					if _, err := os.Stat(destPath); os.IsNotExist(err) {
						err := copyFileWithIO(libPath, destPath)
						if err != nil {
							fmt.Printf("Warning: Failed to copy %s: %v\n", libPath, err)
						} else if verboseFlag {
							fmt.Printf("Copied: %s to %s\n", libPath, destPath)
						}
					}
				}
			}
		}
	}

	return nil
}

func processLibrariesMacOS(libPath string) error {
	if verboseFlag {
		fmt.Printf("Processing library: %s\n", libPath)
	}

	err := updateMacOSLibPaths(libPath)
	if err != nil {
		return err
	}

	err = addRPATHMacOS(libPath)
	if err != nil {
		return err
	}

	// Update the library's own identity to use @rpath if it's not a system library
	if !isSystemLibrary(libPath) {
		err = updateLibraryIdentity(libPath)
		if err != nil {
			fmt.Printf("Warning: Failed to update library identity for %s: %v\n", libPath, err)
		}
	}

	output, err := exec.Command("otool", "-L", libPath).Output()
	if err != nil {
		return fmt.Errorf("error listing shared libraries for %s: %v", libPath, err)
	}

	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i == 0 { // Skip the first line as it's the library itself
			continue
		}
		if strings.Contains(line, "/") {
			parts := strings.Fields(strings.TrimSpace(line))
			if len(parts) > 0 {
				depLibPath := parts[0]
				if !isSystemLibrary(depLibPath) {
					destPath := filepath.Join(outputDir, "lib", filepath.Base(depLibPath))
					if _, err := os.Stat(destPath); os.IsNotExist(err) {
						err := copyFileWithIO(depLibPath, destPath)
						if err != nil {
							fmt.Printf("Warning: Failed to copy %s: %v\n", depLibPath, err)
						} else {
							err = processLibrariesMacOS(destPath)
							if err != nil {
								fmt.Printf("Warning: Failed to process %s: %v\n", destPath, err)
							}
						}
					}
				}
			}
		}
	}

	return nil
}

func setPermissionsRecursively(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("Warning: Path does not exist, skipping: %s\n", path)
				return nil
			}
			return err
		}

		if info.IsDir() {
			return os.Chmod(path, 0755)
		}
		return os.Chmod(path, 0744)
	})
}

func applyFinalPermissions(fileOperations []FileOperation) error {
	for _, op := range fileOperations {
		if op.IsSymlink {
			continue // Skip symlinks
		}

		err := os.Chmod(op.Destination, op.Permissions)
		if err != nil {
			return fmt.Errorf("error setting permissions for %s: %v", op.Destination, err)
		}

		if verboseFlag {
			fmt.Printf("Applied final permissions %s to: %s\n", op.Permissions, op.Destination)
		}
	}
	return nil
}

func createArchive() error {
	archiveName := fmt.Sprintf("%s.tar.gz", outputDir)
	file, err := os.Create(archiveName)
	if err != nil {
		return err
	}
	defer file.Close()

	gzw := gzip.NewWriter(file)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	return filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(filepath.Dir(outputDir), path)
		if err != nil {
			return err
		}
		header.Name = relPath

		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err := os.Readlink(path)
			if err != nil {
				return fmt.Errorf("error reading symlink: %v", err)
			}
			header.Linkname = linkTarget
		}

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = io.Copy(tw, file)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func buildAndInstallWrapper() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("wrapper is only supported on Linux")
	}
	// Create a temporary directory for the wrapper source code
	tempDir, err := os.MkdirTemp("", "wrapper")
	if err != nil {
		return fmt.Errorf("error creating temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Write the wrapper source code to a file
	wrapperSourceData, err := wrapperSource.ReadFile("wrapper/wrapper.c")
	if err != nil {
		return fmt.Errorf("error reading embedded wrapper source code: %v", err)
	}

	wrapperFilePath := filepath.Join(tempDir, "wrapper.c")
	err = os.WriteFile(wrapperFilePath, wrapperSourceData, 0744)
	if err != nil {
		return fmt.Errorf("error writing wrapper source code: %v", err)
	}

	// Build the wrapper executable
	wrapperExecutablePath := filepath.Join(outputDir, "bin", "wrapper")
	cmd := exec.Command("gcc", "-static", "-o", wrapperExecutablePath, "-L", "/usr/lib/x86_64-linux-gnu/", "-L", "/usr/lib/aarch64-linux-gnu/", wrapperFilePath)
	err = cmd.Run()
	if err != nil {
		// Try building with clang if gcc fails
		cmd = exec.Command("clang", "-static", "-o", wrapperExecutablePath, "-L", "/usr/lib/x86_64-linux-gnu/", "-L", "/usr/lib/aarch64-linux-gnu/", wrapperFilePath)
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("error building wrapper executable with both gcc and clang: %v", err)
		}
	}

	if verboseFlag {
		fmt.Printf("Built wrapper executable: %s\n", wrapperExecutablePath)
	}

	return nil
}

func renameAndCreateSymlink(executablePath string) error {
	dir := filepath.Dir(executablePath)
	baseName := filepath.Base(executablePath)

	// Don't rename the wrapper itself
	if baseName == "wrapper" {
		return nil
	}

	dotPrefixedName := filepath.Join(dir, "."+baseName)

	// Rename the original executable with a dot prefix
	err := os.Rename(executablePath, dotPrefixedName)
	if err != nil {
		return fmt.Errorf("error renaming executable: %v", err)
	}

	// Create a symlink to the wrapper tool
	err = os.Symlink("./wrapper", executablePath)
	if err != nil {
		return fmt.Errorf("error creating symlink to wrapper: %v", err)
	}

	if verboseFlag {
		fmt.Printf("Renamed executable to: %s and created symlink to wrapper: %s\n", dotPrefixedName, executablePath)
	}

	return nil
}

func isNixPkg(path string) bool {
	return strings.Contains(path, "/nix/store/")
}

func isHomebrewPkg(path string) bool {
	// Check for common Homebrew paths
	return strings.Contains(path, "/opt/homebrew/Cellar/") || 
	       strings.Contains(path, "/usr/local/Cellar/") ||
	       strings.Contains(path, "/opt/homebrew/bin/") ||
	       strings.Contains(path, "/usr/local/bin/")
}

func planNixPkgFiles(binaryPath string, ignorePatterns []string) ([]FileOperation, error) {
	var fileOperations []FileOperation

	nixPkgDir := filepath.Dir(filepath.Dir(binaryPath))

	err := filepath.Walk(nixPkgDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				return fmt.Errorf("error planning nix package files: %v", err)
			}
			return err
		}

		// Skip bin directories
		if info.IsDir() && filepath.Base(path) == "bin" {
			return filepath.SkipDir
		}

		relPath, err := filepath.Rel(nixPkgDir, path)
		if err != nil {
			return err
		}

		destPath := filepath.Join(outputDir, relPath)

		if !shouldIgnore(path, ignorePatterns) {
			fileOp := FileOperation{
				Source:      path,
				Destination: destPath,
				IsSymlink:   info.Mode()&os.ModeSymlink != 0,
				IsDirectory: info.IsDir(),
				Permissions: info.Mode().Perm(),
			}

			if fileOp.IsSymlink {
				linkTarget, err := os.Readlink(path)
				if err != nil {
					return fmt.Errorf("error reading symlink %s: %v", path, err)
				}
				fileOp.LinkTarget = linkTarget
			}

			fileOperations = append(fileOperations, fileOp)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error planning nix package files: %v", err)
	}

	return fileOperations, nil
}

func planHomebrewPkgFiles(binaryPath string, ignorePatterns []string) ([]FileOperation, error) {
	var fileOperations []FileOperation

	// Find the Homebrew package directory
	// For paths like /opt/homebrew/bin/zeek or /opt/homebrew/Cellar/zeek-full/7.1.1/bin/zeek
	var homebrewPkgDir string
	
	if strings.Contains(binaryPath, "/Cellar/") {
		// Extract the Cellar path: /opt/homebrew/Cellar/package-name/version/
		parts := strings.Split(binaryPath, "/Cellar/")
		if len(parts) >= 2 {
			// Get the part after /Cellar/
			cellPart := parts[1]
			// Split by / and take first two parts (package-name/version)
			cellParts := strings.Split(cellPart, "/")
			if len(cellParts) >= 2 {
				homebrewPkgDir = filepath.Join(parts[0], "Cellar", cellParts[0], cellParts[1])
			}
		}
	} else if strings.Contains(binaryPath, "/opt/homebrew/bin/") || strings.Contains(binaryPath, "/usr/local/bin/") {
		// For binaries in /opt/homebrew/bin/, we need to find their actual package
		// This is more complex - we'd need to resolve symlinks and find the real location
		// For now, let's try to resolve the symlink
		resolvedPath, err := filepath.EvalSymlinks(binaryPath)
		if err == nil && strings.Contains(resolvedPath, "/Cellar/") {
			// Recursively call with the resolved path
			return planHomebrewPkgFiles(resolvedPath, ignorePatterns)
		}
		// If we can't resolve it, we'll skip the homebrew package handling
		if verboseFlag {
			fmt.Printf("Warning: Could not resolve homebrew package directory for %s\n", binaryPath)
		}
		return fileOperations, nil
	}

	if homebrewPkgDir == "" {
		if verboseFlag {
			fmt.Printf("Warning: Could not determine homebrew package directory for %s\n", binaryPath)
		}
		return fileOperations, nil
	}

	if verboseFlag {
		fmt.Printf("Planning homebrew package files from: %s\n", homebrewPkgDir)
	}

	// Walk the Homebrew package directory, similar to Nix packages
	err := filepath.Walk(homebrewPkgDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				if verboseFlag {
					fmt.Printf("Warning: Permission denied for %s, skipping\n", path)
				}
				return nil // Skip permission denied files/dirs
			}
			return err
		}

		// Skip bin directories (we already handle the binary separately)
		if info.IsDir() && filepath.Base(path) == "bin" {
			return filepath.SkipDir
		}

		relPath, err := filepath.Rel(homebrewPkgDir, path)
		if err != nil {
			return err
		}

		destPath := filepath.Join(outputDir, relPath)

		if !shouldIgnore(relPath, ignorePatterns) {
			fileOp := FileOperation{
				Source:      path,
				Destination: destPath,
				IsSymlink:   info.Mode()&os.ModeSymlink != 0,
				IsDirectory: info.IsDir(),
				Permissions: info.Mode().Perm(),
			}

			if fileOp.IsSymlink {
				linkTarget, err := os.Readlink(path)
				if err != nil {
					return fmt.Errorf("error reading symlink %s: %v", path, err)
				}
				fileOp.LinkTarget = linkTarget
			}

			fileOperations = append(fileOperations, fileOp)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error planning homebrew package files: %v", err)
	}

	return fileOperations, nil
}
