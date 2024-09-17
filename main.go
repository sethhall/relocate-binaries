package main

import (
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
	binaries    []string
	helpFlag    bool
	verboseFlag bool
	sensorDir   string
)

func init() {
	flag.Func("p", "Specify a binary to package (can be used multiple times)", func(s string) error {
		binaries = append(binaries, s)
		return nil
	})
	flag.BoolVar(&helpFlag, "help", false, "Display help information")
	flag.BoolVar(&verboseFlag, "v", false, "Enable verbose output")
	flag.Usage = usage
}

func usage() {
	fmt.Fprintf(os.Stderr, `Sensor Setup Tool

This program packages specified binaries along with their dependencies into a 'sensor' directory.
It copies the binaries, their shared libraries, and sets up the correct RPATH.

Usage:
  %s -p <binary1> [-p <binary2> ...] [-v]

Flags:
`, os.Args[0])
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Examples:
  %s -p zeek -p suricata
  %s -p /nix/store/*/bin/zeek -p /nix/store/*/bin/suricata -v

The program will create a 'sensor' directory in the current working directory with the following structure:
  sensor/
    ├── bin/
    │   ├── binary1
    │   └── binary2
    └── lib/
        └── (shared libraries)

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

	var err error
	sensorDir, err = filepath.Abs("sensor")
	if err != nil {
		fmt.Printf("Error getting absolute path for sensor directory: %v\n", err)
		return
	}

	// Create directories
	err = os.MkdirAll(filepath.Join(sensorDir, "bin"), 0755)
	if err != nil {
		fmt.Printf("Error creating sensor/bin directory: %v\n", err)
		return
	}
	err = os.MkdirAll(filepath.Join(sensorDir, "lib"), 0755)
	if err != nil {
		fmt.Printf("Error creating sensor/lib directory: %v\n", err)
		return
	}

	// Copy specified binaries and their shared libraries
	for _, binary := range binaries {
		err := copyBinaryAndLibs(binary)
		if err != nil {
			fmt.Printf("Error processing binary %s: %v\n", binary, err)
		}
	}

	// Update RPATH and relocate libraries
	for _, dir := range []string{"bin", "lib"} {
		err = filepath.Walk(filepath.Join(sensorDir, dir), func(path string, info os.FileInfo, err error) error {
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
					err = addRPATHLinux(path)
					if err != nil {
						fmt.Printf("Warning: %v\n", err)
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

	fmt.Println("All operations completed.")
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

	// Copy the binary to final location
	destPath := filepath.Join(sensorDir, "bin", filepath.Base(binaryPath))
	err = copyFileWithIO(binaryPath, destPath)
	if err != nil {
		return fmt.Errorf("error copying binary %s: %v", binary, err)
	}
	if verboseFlag {
		fmt.Printf("Copied binary: %s to %s\n", binaryPath, destPath)
	}

	// Copy shared libraries
	return copySharedLibraries(binaryPath)
}

func copySharedLibraries(binaryPath string) error {
	var output []byte
	var err error

	if verboseFlag {
		fmt.Printf("Copying shared libraries for: %s\n", binaryPath)
	}

	if runtime.GOOS == "darwin" {
		output, err = exec.Command("otool", "-L", binaryPath).Output()
	} else {
		output, err = exec.Command("ldd", binaryPath).Output()
	}

	if err != nil {
		return fmt.Errorf("error listing shared libraries: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		// Skip the first line on macOS as it's the binary itself
		if runtime.GOOS == "darwin" && i == 0 {
			continue
		}

		var libPath string
		if runtime.GOOS == "darwin" {
			if strings.Contains(line, "/") {
				libPath = strings.Fields(strings.TrimSpace(line))[0]
				if isSystemLibrary(libPath) {
					continue
				}
			}
		} else {
			if strings.Contains(line, "=>") && !strings.Contains(line, "linux-vdso.so") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					libPath = parts[2]
				}
			}
		}
		if libPath != "" && libPath != binaryPath {
			destPath := filepath.Join(sensorDir, "lib", filepath.Base(libPath))
			err := copyFileWithIO(libPath, destPath)
			if err != nil {
				fmt.Printf("Warning: Failed to copy %s: %v\n", libPath, err)
			} else if verboseFlag {
				fmt.Printf("Copied: %s to %s\n", libPath, destPath)
			}
		}
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
		// If the link is relative, make it absolute
		if !filepath.IsAbs(linkTarget) {
			linkTarget = filepath.Join(filepath.Dir(src), linkTarget)
		}
		return copyFileWithIO(linkTarget, dst)
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
		return fmt.Errorf("error setting destination file mode: %v", err)
	}

	if verboseFlag {
		fmt.Printf("Successfully copied: %s to %s\n", src, dst)
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
	absLibPath := filepath.Join(sensorDir, "lib")
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

func addRPATHLinux(path string) error {
	cmd := exec.Command("patchelf", "--print-rpath", path)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("error checking RPATH for %s: %v", path, err)
	}

	if !strings.Contains(string(output), "$ORIGIN/../lib") {
		cmd = exec.Command("patchelf", "--set-rpath", "$ORIGIN/../lib", path)
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
					destPath := filepath.Join(sensorDir, "lib", filepath.Base(libPath))
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
					destPath := filepath.Join(sensorDir, "lib", filepath.Base(depLibPath))
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
