# Relocate Binaries Tool

[![CI](https://github.com/sethhall/relocate-binaries/actions/workflows/ci.yml/badge.svg)](https://github.com/sethhall/relocate-binaries/actions/workflows/ci.yml)

## Quick Start

```sh
# Build
make build

# Dry-run on a binary to preview operations
./relocate-binaries -p /usr/bin/curl --dry-run -v

# Create a relocatable bundle
./relocate-binaries -p /usr/bin/curl -output output -install-path /opt/curl
```

## Description

The Binary Relocation Tool is a Go program designed for Linux and MacOS to package binaries along with all their dependencies. This tool creates fully self-contained executable packages that can run on systems with minimal or no system libraries, such as containers based on empty file systems.

## Features

- Packages specified binaries with ALL their dependencies, including core system libraries (on Linux)
- Includes the necessary dynamic loader (ld-linux) in the package
- Creates a fully self-contained and relocatable directory structure
- Supports Linux and MacOS environments
- Minimizes or eliminates reliance on the host system's libraries
- Ideal for use in containerized environments or systems with limited libraries

## Requirements

- Go 1.23+
- Access to the target binaries and their associated system libraries
- macOS: otool, install_name_tool (Xcode Command Line Tools)
- Linux: ldd, patchelf, file, gcc or clang (for building the Linux wrapper)

## Installation

Build from source:
```sh
make build
# or
go build -o relocate-binaries main.go
```

1. Clone this repository:
   ```
   git clone https://github.com/sethhall/relocate-binaries.git
   ```
2. Navigate to the project directory:
   ```
   cd relocate-binaries
   ```
3. Build the project:
   ```
   go build
   ```

## Usage

Run the tool with the following command:

```sh
Usage:

  ./relocate-binaries -p <binary1> [-p <binary2> ...] [-v] [-archive] [-output <directory>] [-install-path <path>] [-f]

Flags:

  -archive
        Create a compressed archive of the final bundle
  -f
        Force the tool to proceed even if the output directory exists
  -help
        Display help information
  -install-path string
        Specify the final installation path for the package
  -output string
        Specify the output directory (default "output")
  -p value
        Specify a binary to package (can be used multiple times)
  -v    Enable verbose output
```

Examples:

Single binary (verbose):
```sh
./relocate-binaries -p /usr/bin/python3 -v -output output -install-path /opt/python
```

Multiple binaries in one bundle:
```sh
./relocate-binaries -p /usr/bin/nginx -p /usr/sbin/php-fpm -v -output web_stack -install-path /opt/web
```

Use an ignore file to exclude files from the bundle:
```sh
# .bundleignore example
cat > /tmp/.bundleignore <<'EOF'
lib/*
/usr/share/doc/*
*.debug
EOF

./relocate-binaries -p /usr/bin/python3 -output filtered -ignore-file /tmp/.bundleignore
```

Create a compressed archive of the bundle:
```sh
./relocate-binaries -p /usr/bin/python3 -v -archive -output custom_output -install-path /opt/custom
# Produces custom_output/ and custom_output.tar.gz
```

Nix store example:
```sh
./relocate-binaries -p /nix/store/*/bin/zeek -p /nix/store/*/bin/suricata -v -archive -output custom_sensor -install-path /opt/sensor
```

## macOS vs Linux behavior

- macOS uses otool and install_name_tool to:
  - Add @executable_path/../lib and @loader_path/../lib RPATHs
  - Rewrite absolute library paths to @rpath/ relative paths
  - Recursively process dependent libraries
- Linux uses ldd and patchelf and introduces a wrapper mechanism:
  - Original executables are renamed with a dot prefix (e.g., .binary)
  - A tiny C wrapper is built and placed at bin/wrapper
  - Symlinks in bin/ point to the wrapper which locates the packaged ld-linux and then runs .binary
  - RPATH is set to $ORIGIN/../lib and the ELF interpreter can be set to the packaged loader when -install-path is provided

## Output

The program will create a directory (default name: 'output') in the current working directory with the following structure:

```
output/
├── bin/
│ ├── binary1
│ └── binary2
├── lib/
│ ├── libc.so.6
│ ├── ld-linux-x86-64.so.2
│ └── (other required shared libraries)
└── (other necessary files or directories)
```

## How It Works

1. The tool analyzes the specified binaries to identify all required shared libraries.
2. It copies these libraries, including core system libraries like libc, into the package. On MacOS, system libraries are not included.
3. The dynamic loader (ld-linux) is also included in the package.
4. Binaries are modified to use the packaged libraries and loader instead of system versions.
5. The resulting package is self-contained and can run on systems with minimal library support.

## Use Cases

- Creating fully self-contained applications for minimal containerized environments
- Deploying applications to systems with unknown or minimal library availability
- Ensuring consistent library versions across different deployment environments
- Isolating applications from system library changes

## Testing

Run the cross-platform integration tests:
```sh
make test
# or
go test -v ./...
```

Quick local smoke tests (macOS or Linux):
```sh
chmod +x scripts/smoke.sh
scripts/smoke.sh
```

Notes:
- On macOS, tests that exercise non-system library copying prefer /opt/homebrew/bin/python3. If not present, those tests are skipped with guidance.
- On Linux, ensure ldd, patchelf, file, and gcc or clang are installed.

## Notes

- This tool requires appropriate permissions to read system libraries and modify binaries.
- The resulting packages may be larger than typical deployments due to the inclusion of core libraries.
- While designed for Linux and MacOS, the concept could potentially be extended to other operating systems.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## CI

GitHub Actions runs the test suite on Ubuntu and macOS for pushes and PRs. See the badge above or open the workflow:
- .github/workflows/ci.yml

## Troubleshooting

- required tool 'X' not found in PATH
  - Ensure platform tools are installed:
    - macOS: Xcode Command Line Tools (otool, install_name_tool)
    - Linux: ldd, patchelf, file, gcc or clang
- Error: Output directory <dir> already exists. Use -f flag to force
  - Re-run with -f or remove the directory.
- Dry-run created files
  - By design, --dry-run should not create the output directory. If you see files, ensure you didn’t run without --dry-run earlier into the same path.
- macOS: library copying seems to include only system libs
  - System libs under /usr/lib and /System/Library are intentionally skipped. Use a non-system binary (e.g., /opt/homebrew/bin/python3) to exercise copying.
- Linux: wrapper not built
  - Ensure gcc or clang is present; the wrapper is only compiled on Linux.

## Disclaimer

This tool creates self-contained binary packages by including system libraries. Ensure you comply with all relevant licenses when redistributing these packages. Always test packaged binaries in a safe environment before deployment.
