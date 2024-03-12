# mkcheck2

mkcheck2 is a build system dependency tracer and analyzer that uses eBPF to track file accesses during build processes. It helps understand how builds work and identify potential build inconsistencies.

## Overview

mkcheck2 captures detailed information about file system operations during build execution, including:
- File reads and writes
- File renames, links, and deletions
- Process execution chains
- Directory changes

This information can be used to:
- Visualize build dependencies
- Compare builds for inconsistencies 
- Debug build issues
- Optimize build configurations

## Building mkcheck2

Prerequisites:
- Swift compiler
- CMake
- Ninja
- Linux kernel with eBPF support

Build steps:
```bash
# Generate the build files with CMake
cmake -G Ninja -B build

# Build the C components
ninja -C build

# Build the Swift components
swift build
```

## Usage

### Tracing a Command

```bash
# Specify output format and file
sudo ./.build/debug/mkcheck2 -o trace.json -f json -- make
```

### Tracing an Existing Process

```bash
# Trace by PID
sudo ./.build/debug/mkcheck2 pid 1234
```

### Comparing Trace Files

```bash
# Compare two trace files to find differences
./.build/debug/mkcheck2 diff trace1.json trace2.json
```

## Output Formats

- `json`: Detailed JSON format for full analysis
- `dot`: Graphviz DOT format for dependency visualization
- `ascii`: Human-readable ASCII output
- `none`: No output (useful for testing)

## Options

- `-o, --output`: Specify output file
- `-f, --format`: Specify output format (json, dot, ascii, none)
- `--log-level`: Set log level (trace, debug, info, notice, warning, error, critical)

## License

MIT License
