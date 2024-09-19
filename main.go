package main

import (
	"archive/tar"
	"compress/gzip"
	"embed"
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
	externalTools    = map[string][]string{
		"darwin": {"otool", "install_name_tool"},
		"linux":  {"ldd", "patchelf", "file"},
	}
)

//go:embed wrapper.c
var wrapperSource embed.FS

func init() {
	flag.Func("p", "Specify a binary to package (can be used multiple times)", func(s string) error {
		binaries = append(binaries, s)
		return nil
	})
	flag.BoolVar(&helpFlag, "help", false, "Display help information")
	flag.BoolVar(&verboseFlag, "v", false, "Enable verbose output")
	flag.BoolVar(&archiveFlag, "archive", false, "Create a compressed archive of the final bundle")
	flag.BoolVar(&forceFlag, "f", false, "Force the tool to proceed even if the output directory exists")
	flag.StringVar(&outputDir, "output", "output", "Specify the output directory")
	flag.StringVar(&finalInstallPath, "install-path", "", "Specify the final installation path for the package")
	flag.Usage = usage
}

func usage() {
	fmt.Fprintf(os.Stderr, `Sensor Setup Tool

This program packages specified binaries along with their dependencies into a 'sensor' directory.

It copies the binaries, their shared libraries, and sets up the correct RPATH.

Usage:

  %s -p <binary1> [-p <binary2> ...] [-v] [-archive] [-output <directory>] [-install-path <path>] [-f]

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

	// Copy specified binaries and their shared libraries
	for _, binary := range binaries {
		err := copyBinaryAndLibs(binary)
		if err != nil {
			fmt.Printf("Error processing binary %s: %v\n", binary, err)
			if strings.Contains(err.Error(), "missing libraries") {
				fmt.Println("Failure due to missing libraries!")
				os.Exit(1)
			}
		}
	}

	// Set permissions recursively
	err = setPermissionsRecursively(outputDir)
	if err != nil {
		fmt.Printf("Error setting permissions: %v\n", err)
		return
	}

	// Update RPATH and relocate libraries
	for _, dir := range []string{"bin", "lib"} {
		err = filepath.Walk(filepath.Join(outputDir, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				if runtime.GOOS == "darwin" {
					err = processLibrariesRecursively(path)
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

func copyBinaryAndLibs(binary string) error {
	// Find the binary
	binaryPath, err := exec.LookPath(binary)
	if err != nil {
		return fmt.Errorf("error finding %s: %v", binary, err)
	}

	// Get absolute path
	binaryPath, err = filepath.Abs(binaryPath)
	if err != nil {
		return fmt.Errorf("error getting absolute path for %s: %v", binary, err)
	}

	// Create the output directory if it does not exist
	err = os.MkdirAll(filepath.Join(outputDir, "bin"), 0755)
	if err != nil {
		return fmt.Errorf("error creating output directory: %v", err)
	}

	// Copy the binary to final location
	destPath := filepath.Join(outputDir, "bin", filepath.Base(binaryPath))
	err = copyFileWithIO(binaryPath, destPath)
	if err != nil {
		return fmt.Errorf("error copying binary %s: %v", binary, err)
	}

	if verboseFlag {
		fmt.Printf("Copied binary: %s to %s\n", binaryPath, destPath)
	}

	// Check if the binary is a nix package
	if isNixPkg(binaryPath) {
		if verboseFlag {
			fmt.Printf("Detected nix package: %s - Copying other package files...\n", binaryPath)
		}
		err = copyNixPkgFiles(binaryPath)
		if err != nil {
			return fmt.Errorf("error copying nix package files for %s: %v", binary, err)
		}
	}

	// Copy shared libraries
	err = copySharedLibraries(binaryPath)
	if err != nil {
		return fmt.Errorf("error copying shared libraries for %s: %v", binary, err)
	}

	// Set RPATH for the copied binary
	err = addRPATHLinux(destPath)
	if err != nil {
		return fmt.Errorf("error setting RPATH for %s: %v", destPath, err)
	}

	// Rename the original executable with a dot prefix and create a symlink to the wrapper tool on Linux
	if runtime.GOOS == "linux" {
		err = renameAndCreateSymlink(destPath)
		if err != nil {
			return fmt.Errorf("error renaming and creating symlink for %s: %v", destPath, err)
		}
	}

	return nil
}

func copySharedLibraries(binaryPath string) error {
	if verboseFlag {
		fmt.Printf("Copying shared libraries for: %s\n", binaryPath)
	}

	output, err := exec.Command("ldd", binaryPath).Output()
	if err != nil {
		return fmt.Errorf("error listing shared libraries: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	missingLibraries := []string{}
	for _, line := range lines {
		if strings.Contains(line, "=>") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				if parts[2] == "not" {
					missingLibraries = append(missingLibraries, parts[0])
				} else {
					libPath := parts[2]
					destPath := filepath.Join(outputDir, "lib", filepath.Base(libPath))
					err := copyFileWithIO(libPath, destPath)
					if err != nil {
						fmt.Printf("Warning: Failed to copy %s: %v\n", libPath, err)
					} else {
						if verboseFlag {
							fmt.Printf("Copied: %s to %s\n", libPath, destPath)
						}

						// Set RPATH for the copied library
						err = addRPATHLinux(destPath)
						if err != nil {
							fmt.Printf("Warning: Failed to set RPATH for %s: %v\n", destPath, err)
						}
					}
				}
			}
			// Handle ldd output without "=>" when ld-linux- is displayed weird.
		} else if strings.Contains(line, "ld-linux-") {
			libPath := strings.Fields(line)[0]
			destPath := filepath.Join(outputDir, "lib", filepath.Base(libPath))
			err := copyFileWithIO(libPath, destPath)
			if err != nil {
				fmt.Printf("Warning: Failed to copy %s: %v\n", libPath, err)
			} else {
				if verboseFlag {
					fmt.Printf("Copied: %s to %s\n", libPath, destPath)
				}

				// Set RPATH for the copied library
				err = addRPATHLinux(destPath)
				if err != nil {
					fmt.Printf("Warning: Failed to set RPATH for %s: %v\n", destPath, err)
				}
			}
		}
	}

	if len(missingLibraries) > 0 {
		return fmt.Errorf("missing libraries: %v", missingLibraries)
	}

	return nil
}

func isSystemLibrary(path string) bool {
	systemPaths := []string{
		"/usr/lib",
		"/System/Library",
	}
	for _, sysPath := range systemPaths {
		if strings.HasPrefix(path, sysPath) {
			return true
		}
	}
	return false
}

func copyFileWithIO(src, dst string) error {
	if verboseFlag {
		fmt.Printf("Attempting to copy: %s to %s\n", src, dst)
	}

	// Check if destination file already exists
	if _, err := os.Stat(dst); err == nil {
		if verboseFlag {
			fmt.Printf("File already exists, skipping: %s\n", dst)
		}
		return nil
	}

	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("error opening source file: %v", err)
	}
	defer sourceFile.Close()

	// Get file info to check if it's a symlink
	fileInfo, err := sourceFile.Stat()
	if err != nil {
		return fmt.Errorf("error getting file info: %v", err)
	}

	// If it's a symlink, read the link and copy the target
	if fileInfo.Mode()&os.ModeSymlink != 0 {
		linkTarget, err := os.Readlink(src)
		if err != nil {
			return fmt.Errorf("error reading symlink: %v", err)
		}
		// Create the symlink at the destination
		err = os.Symlink(linkTarget, dst)
		if err != nil {
			return fmt.Errorf("error creating symlink: %v", err)
		}
		if verboseFlag {
			fmt.Printf("Successfully created symlink: %s -> %s\n", dst, linkTarget)
		}
		return nil
	}

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("error creating destination file: %v", err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return fmt.Errorf("error copying file contents: %v", err)
	}

	// Copy mode from source to destination
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("error getting source file info: %v", err)
	}

	err = os.Chmod(dst, srcInfo.Mode())
	if err != nil {
		return fmt.Errorf("error setting file permissions: %v", err)
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
	cmd := exec.Command("otool", "-l", path)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("error checking RPATH for %s: %v", path, err)
	}

	if !strings.Contains(string(output), "@executable_path/../lib") {
		cmd = exec.Command("install_name_tool", "-add_rpath", "@executable_path/../lib", path)
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("failed to add RPATH for %s: %v", path, err)
		}
		if verboseFlag {
			fmt.Printf("Added RPATH to: %s\n", path)
		}
	} else if verboseFlag {
		fmt.Printf("RPATH already exists for: %s\n", path)
	}

	// Also add the absolute path to the lib directory
	absLibPath := filepath.Join(outputDir, "lib")
	if !strings.Contains(string(output), absLibPath) {
		cmd = exec.Command("install_name_tool", "-add_rpath", absLibPath, path)
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("failed to add absolute RPATH for %s: %v", path, err)
		}
		if verboseFlag {
			fmt.Printf("Added absolute RPATH to: %s\n", path)
		}
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

func processLibrariesRecursively(libPath string) error {
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
							err = processLibrariesRecursively(destPath)
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
				return nil // Skip non-existent files or directories
			}
			return err
		}
		if info.IsDir() {
			return os.Chmod(path, 0755)
		}
		return os.Chmod(path, 0755)
	})
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
	err = os.WriteFile(wrapperFilePath, wrapperSourceData, 0644)
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
	dotPrefixedName := filepath.Join(dir, "." + baseName)

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

func isNixPkg(binaryPath string) bool {
	return strings.Contains(binaryPath, "/nix/store/")
}

func copyNixPkgFiles(binaryPath string) error {
	nixStorePath := filepath.Dir(filepath.Dir(binaryPath))
	err := filepath.Walk(nixStorePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(nixStorePath, path)
		if err != nil {
			return err
		}
		destPath := filepath.Join(outputDir, relPath)
		if info.IsDir() {
			return os.MkdirAll(destPath, info.Mode())
		}
		return copyFileWithIO(path, destPath)
	})
	if err != nil {
		return fmt.Errorf("error copying nix package files: %v", err)
	}
	return nil
}
