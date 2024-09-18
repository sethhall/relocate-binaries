# Relocate Binaries Tool

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

- Go 1.x (where x is the version you're using)
- Access to the target binaries and their associated system libraries

## Installation

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

  ./relocate-binaries -p <binary1> [-p <binary2> ...] [-v] [-archive] [-output <directory>]

Flags:

  -archive
        Create a compressed archive of the final bundle
  -help
        Display help information
  -output string
        Specify the output directory (default "output")
  -p value
        Specify a binary to package (can be used multiple times)
  -v    Enable verbose output```

Examples:
./relocate-binaries -p /usr/bin/python3
./relocate-binaries -p /usr/bin/nginx -p /usr/sbin/php-fpm -v

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

- Creating fully self-contained applications for containerized environments
- Deploying applications to systems with unknown or minimal library availability
- Ensuring consistent library versions across different deployment environments
- Isolating applications from system library changes

## Notes

- This tool requires appropriate permissions to read system libraries and modify binaries.
- The resulting packages may be larger than typical deployments due to the inclusion of core libraries.
- While designed for Linux and MacOS, the concept could potentially be extended to other operating systems.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This tool creates self-contained binary packages by including system libraries. Ensure you comply with all relevant licenses when redistributing these packages. Always test packaged binaries in a safe environment before deployment.
