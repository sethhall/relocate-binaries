package main

import (
	"archive/tar"
	"compress/gzip"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
	externalTools    = map[string][]string{
		"darwin": {"otool", "install_name_tool"},
		"linux":  {"ldd", "patchelf", "file"},
	}
)

//go:embed wrapper.c
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

	// Create directories
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

	// Planning stage: Build the list of FileOperation structs
	var fileOperations []FileOperation
	for _, binary := range binaries {
		ops, err := planFileOperations(binary)
		if err != nil {
			fmt.Printf("Error planning file operations for binary %s: %v\n", binary, err)
			if strings.Contains(err.Error(), "missing libraries") {
				fmt.Println("Failure due to missing libraries!")
				os.Exit(1)
			}
		}
		fileOperations = append(fileOperations, ops...)
	}

	// Dry-run mode: Print the planned operations and exit
	if dryRunFlag {
		fmt.Println("Dry-run mode enabled. Planned file operations:")
		for _, op := range fileOperations {
			fmt.Printf("Source: %s, Destination: %s, IsSymlink: %t, LinkTarget: %s\n", op.Source, op.Destination, op.IsSymlink, op.LinkTarget)
		}
		return
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

func planFileOperations(binary string) ([]FileOperation, error) {
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

	fileOperations = append(fileOperations, FileOperation{
		Source:      binaryPath,
		Destination: destPath,
		IsSymlink:   false,
		IsDirectory: false,
		Permissions: fileInfo.Mode().Perm(),
	})

	// Plan shared libraries copy operations
	ops, err := planSharedLibraries(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("error planning shared libraries for %s: %v", binary, err)
	}

	fileOperations = append(fileOperations, ops...)

	// Handle nix packages
	if isNixPkg(binaryPath) {
		if verboseFlag {
			fmt.Printf("Detected nix package: %s\n", binaryPath)
		}
		ops, err := planNixPkgFiles(binaryPath)
		if err != nil {
			return nil, fmt.Errorf("error planning nix package files for %s: %v", binary, err)
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

func planSharedLibraries(binaryPath string) ([]FileOperation, error) {
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
		return planSharedLibrariesMacOS(lines, binaryPath)
	} else {
		return planSharedLibrariesLinux(lines, binaryPath)
	}
}

func planSharedLibrariesMacOS(lines []string, binaryPath string) ([]FileOperation, error) {
	var fileOperations []FileOperation
	seenDestinations := make(map[string]bool)

	for i, line := range lines {
		if i == 0 || len(strings.TrimSpace(line)) == 0 {
			continue // Skip the first line (binary path) and empty lines
		}
		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) >= 1 {
			libPath := parts[0]
			if !isSystemLibrary(libPath) {
				destPath := filepath.Join(outputDir, "lib", filepath.Base(libPath))
				fileOps, err := createFileOperation(libPath, destPath)
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

func planSharedLibrariesLinux(lines []string, binaryPath string) ([]FileOperation, error) {
	var fileOperations []FileOperation
	seenDestinations := make(map[string]bool)
	var missingLibraries []string

	for _, line := range lines {
		if strings.Contains(line, "=>") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				if parts[2] == "not" {
					missingLibraries = append(missingLibraries, parts[0])
				} else {
					libPath := parts[2]
					destPath := filepath.Join(outputDir, "lib", filepath.Base(libPath))
					fileOps, err := createFileOperation(libPath, destPath)
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
		} else if strings.Contains(line, "ld-linux-") {
			libPath := strings.Fields(line)[0]
			destPath := filepath.Join(outputDir, "lib", filepath.Base(libPath))
			fileOps, err := createFileOperation(libPath, destPath)
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

	if len(missingLibraries) > 0 {
		return nil, fmt.Errorf("missing libraries: %v", missingLibraries)
	}

	return fileOperations, nil
}

func createFileOperation(sourcePath, destPath string) ([]FileOperation, error) {
	fileInfo, err := os.Lstat(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("error getting file info for %s: %v", sourcePath, err)
	}

	fileOp := FileOperation{
		Source:      sourcePath,
		Destination: destPath,
		IsSymlink:   fileInfo.Mode()&os.ModeSymlink != 0,
		IsDirectory: fileInfo.IsDir(),
		Permissions: fileInfo.Mode().Perm(),
	}

	if fileOp.IsSymlink {
		linkTarget, err := os.Readlink(sourcePath)
		if err != nil {
			return nil, fmt.Errorf("error reading symlink %s: %v", sourcePath, err)
		}
		fileOp.LinkTarget = linkTarget

		// If the symlink is relative, make it absolute
		if !filepath.IsAbs(linkTarget) {
			fileOp.LinkTarget = filepath.Join(filepath.Dir(sourcePath), linkTarget)
		}

		// Add the target file as well
		targetFileOps, err := createFileOperation(fileOp.LinkTarget, filepath.Join(filepath.Dir(destPath), filepath.Base(fileOp.LinkTarget)))
		if err != nil {
			return nil, err
		}

		return append([]FileOperation{fileOp}, targetFileOps...), nil
	}

	return []FileOperation{fileOp}, nil
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
	wrapperSourceData, err := wrapperSource.ReadFile("wrapper.c")
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

func planNixPkgFiles(binaryPath string) ([]FileOperation, error) {
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

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error planning nix package files: %v", err)
	}

	return fileOperations, nil
}
