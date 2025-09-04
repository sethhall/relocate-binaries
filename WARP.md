# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

The Binary Relocation Tool is a Go program for Linux and macOS that packages binaries with all their dependencies to create self-contained executables. It analyzes binary dependencies, copies required shared libraries, and configures proper runtime paths for deployment in containerized or minimal environments.

## Development Commands

### Build and Development
```bash
# Build the main binary
go build -o relocate-binaries main.go
# Or use the Makefile
make build

# Run with verbose output
./relocate-binaries -p /path/to/binary -v

# Create a package with archive
./relocate-binaries -p /path/to/binary -archive -output custom_output
```

### Testing Binary Dependencies
```bash
# Test dependency analysis on Linux
ldd /path/to/binary

# Test dependency analysis on macOS  
otool -L /path/to/binary

# Test with dry-run mode to see planned operations
./relocate-binaries -p /path/to/binary --dry-run
```

### Platform-Specific Requirements
```bash
# Linux: Ensure required tools are available
which ldd patchelf file

# macOS: Ensure required tools are available
which otool install_name_tool
```

## Architecture Overview

### Core Components

**Main Process Flow** (`main.go`):
1. **Planning Stage**: Analyzes binaries and builds `FileOperation` structs for all required files
2. **Filtering Stage**: Applies ignore patterns from optional ignore files  
3. **Execution Stage**: Copies files, handles symlinks, and applies permissions
4. **Relocation Stage**: Updates RPATHs and library paths for the target environment

**Platform-Specific Handlers**:
- **Linux**: Uses `ldd`, `patchelf`, and a custom C wrapper (`wrapper/wrapper.c`) for dynamic loading
- **macOS**: Uses `otool` and `install_name_tool` for Mach-O binary manipulation

**Key Data Structures**:
- `FileOperation`: Represents file copy/symlink operations with metadata
- `externalTools`: Maps OS-specific required external tools

### Linux-Specific Architecture

**Wrapper System**: On Linux, the tool creates a sophisticated wrapper system:
1. Original executables are renamed with dot prefix (e.g., `.binary`)
2. A compiled C wrapper (`wrapper.c`) replaces the original executable
3. The wrapper dynamically finds and invokes the correct `ld-linux` loader
4. Symlinks point to the wrapper, which redirects to the actual executable

**RPATH Management**: Sets `$ORIGIN/../lib` RPATH for relative library loading and updates interpreter paths to use the packaged dynamic loader.

### macOS-Specific Architecture

**Library Path Updates**: Uses `install_name_tool` to:
- Add `@executable_path/../lib` and `@loader_path/../lib` RPATHs
- Change absolute library paths to `@rpath/` relative references
- Recursively processes library dependencies

### Nix Package Support

Special handling for `/nix/store/` packages:
- Detects Nix packages automatically
- Copies entire package directory structure (excluding bin directories)
- Preserves symlinks and directory hierarchies

### Key Functions by Responsibility

**Planning**: `planFileOperations()`, `planSharedLibraries()`, `planNixPkgFiles()`
**Execution**: `executeFileOperations()`, `copyFileWithIO()`, `createSymlink()`
**Platform-specific**: `addRPATHLinux()`, `processLibrariesMacOS()`, `buildAndInstallWrapper()`
**Filtering**: `shouldIgnore()`, `filterIgnoredFiles()`, `matchWildcard()`

## Configuration

### Ignore Files
Create a `.bundleignore` file (specified with `-ignore-file`) to exclude files from packaging:
```
# Example ignore patterns
/usr/share/doc/*
*.debug
/nix/store/*/share/man/*
```

### Command Line Options
- `-p`: Specify binary to package (repeatable)
- `-output`: Output directory (default: "output")
- `-install-path`: Final installation path for RPATH configuration
- `-archive`: Create compressed tar.gz archive
- `-f`: Force overwrite existing output directory
- `--dry-run`: Preview operations without execution
- `-ignore-file`: Path to bundle ignore file
- `-v`: Verbose output

## Platform Dependencies

**Linux**: `ldd`, `patchelf`, `file`, `gcc` or `clang` (for wrapper compilation)
**macOS**: `otool`, `install_name_tool`

The tool automatically checks for required external tools on startup and fails fast if dependencies are missing.
