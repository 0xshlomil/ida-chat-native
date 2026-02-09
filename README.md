# IDA Chat Native Plugin

Native C++ IDA Pro plugin for AI-powered binary analysis using Claude's tool_use API.

## Prerequisites

- **IDA Pro 9.x** (with SDK from [GitHub](https://github.com/HexRaysSA/ida-sdk))
- **libcurl** development headers
- **CMake 3.27+**
- **C++17 compiler**

### Install dependencies (Ubuntu/Debian)

```bash
sudo apt install libcurl4-openssl-dev qt6-base-dev cmake build-essential
```

### IDA SDK setup

```bash
# Clone the SDK (if not already present as a sibling directory)
git clone https://github.com/HexRaysSA/ida-sdk.git ../idasdk
cd ../idasdk && git submodule update --init --recursive && cd -
```

## Build

```bash
cd ida-chat-native

# Option 1: Auto-detect SDK from sibling idasdk/ directory
cmake -B build
cmake --build build

# Option 2: Specify SDK path explicitly
IDASDK=/path/to/idasdk/src cmake -B build
cmake --build build
```

The plugin is automatically deployed to `$IDASDK/src/bin/plugins/ida-chat.so`.

## Install

Copy the built plugin to IDA's plugins directory:

```bash
cp /path/to/idasdk/src/bin/plugins/ida-chat.so ~/.idapro/plugins/
```

## Configuration

The plugin reads the API key from:

1. `ANTHROPIC_API_KEY` environment variable (highest priority)
2. `~/.idapro/ida-chat.conf` file

Config file format (`~/.idapro/ida-chat.conf`):

```
api_key=sk-ant-...
model=claude-sonnet-4-20250514
max_turns=20
max_tokens=8192
```

If no API key is found, a dialog will prompt you on first use.

## Usage

1. Open IDA Pro with a binary
2. Press **Ctrl+Shift+C** to toggle the chat panel (or View menu)
3. Type a question and press Enter
4. The agent will use IDA SDK tools to analyze the binary and respond

### Example queries

- "What functions are in this binary?"
- "Decompile the main function"
- "What references this function?" (with cursor on a function)
- "Find strings related to passwords"
- "Rename this function to `process_input`"

## Available Tools

The agent has access to 19 IDA SDK tools:

| Tool | Description |
|------|-------------|
| `get_database_info` | Binary metadata (processor, bits, entry points) |
| `list_functions` | List/filter functions with pagination |
| `get_function_info` | Detailed function info (frame, flags) |
| `get_disassembly` | Disassembly listing |
| `decompile` | Hex-Rays decompilation (if available) |
| `get_xrefs_to` | Cross-references TO an address |
| `get_xrefs_from` | Cross-references FROM an address |
| `get_strings` | String search/listing |
| `list_segments` | Binary segments/sections |
| `get_bytes` | Raw byte reading |
| `search_bytes` | Byte pattern search with wildcards |
| `get_names` | Named locations (labels, imports, exports) |
| `rename_address` | Rename a location |
| `set_comment` | Add comments to addresses |
| `set_decompiler_comment` | Add comments to decompiled pseudocode |
| `rename_local_variable` | Rename variables in decompiled pseudocode |
| `set_local_variable_type` | Change variable types in pseudocode |
| `get_current_address` | Get cursor position |
| `jump_to_address` | Navigate IDA view |
