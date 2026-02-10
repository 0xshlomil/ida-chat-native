# IDA Chat Native Plugin

Native C++ IDA Pro plugin for AI-powered binary analysis using Claude's tool_use API.

## Features

- **Native C++ plugin** — no Python runtime, no MCP bridge, no external dependencies at runtime. Single `.so` loaded directly by IDA.
- **Built-in chat UI** — Qt-based chat panel embedded in IDA with full CommonMark markdown rendering (via [md4c](https://github.com/mity/md4c)), Catppuccin theming (dark/light), and configurable font size. Supports code blocks, tables, blockquotes, links, strikethrough, and more.
- **Streaming responses** — text appears incrementally as the LLM generates via SSE streaming, with throttled re-rendering at ~20fps. Supports both Claude and OpenAI streaming formats.
- **Agentic tool-use loop** — the AI autonomously chains multiple tool calls per query (up to configurable max turns) to perform deep analysis.
- **Deep Analyze mode** — one-click recursive analysis that decompiles the function at cursor, renames variables, sets types, detects struct patterns, and recursively processes all callees (up to 100 turns with a specialized system prompt).
- **Multiple backends** — Claude (Anthropic), OpenAI-compatible APIs, and local LLMs (llama.cpp, Ollama, etc.).

### Analysis Tools

| Tool | Description |
|------|-------------|
| `get_database_info` | Binary metadata — processor, bitness, file type, entry points |
| `list_functions` | List/filter functions with pagination |
| `get_function_info` | Detailed function info — size, frame, flags |
| `get_disassembly` | Disassembly listing with bytes, addresses, and comments |
| `decompile` | Hex-Rays decompilation (pseudocode) |
| `get_xrefs_to` | Cross-references TO an address |
| `get_xrefs_from` | Cross-references FROM an address |
| `get_strings` | String search/listing with filtering and min-length |
| `list_segments` | Binary segments/sections with permissions |
| `get_bytes` | Raw byte reading at address |
| `search_bytes` | Byte pattern search with wildcards (e.g. `"48 8B ?? ??"`) |
| `get_names` | Named locations — functions, labels, imports, exports |
| `list_imports` | Imported symbols from external libraries with module names |
| `get_callees` | Functions called by a given function (direct calls) |
| `get_basic_blocks` | Basic blocks with control flow graph (successors/predecessors) |
| `get_callgraph` | Build recursive call graph from root function |
| `get_stack_frame` | Stack frame layout — locals, arguments, saved registers |

### Modification Tools

| Tool | Description |
|------|-------------|
| `rename_address` | Rename functions, labels, and addresses |
| `rename_local_variable` | Rename variables in decompiled pseudocode |
| `set_local_variable_type` | Change variable types in pseudocode |
| `set_function_type` | Apply function prototype/signature (return type, parameters, calling convention) |
| `declare_type` | Declare custom C type (struct/union/typedef/enum) in local type library |
| `define_function` | Create/define function at address where IDA missed one |
| `set_comment` | Add/edit disassembly comments |
| `set_decompiler_comment` | Add/edit pseudocode comments |

### Navigation Tools

| Tool | Description |
|------|-------------|
| `get_current_address` | Get cursor position in IDA |
| `jump_to_address` | Navigate IDA disassembly view to address |

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

Settings can be changed via the in-plugin settings dialog (gear icon) or by editing the config file directly.

### Config file

Located at `~/.idapro/ida-chat.conf`, using `key=value` format (lines starting with `#` are comments):

```
# Backend: "claude" (default) or "openai"
backend=claude

# API key (required for Claude, optional for local LLMs)
api_key=sk-ant-...

# API URL (only needed for OpenAI-compatible backends, ignored for Claude)
api_url=http://localhost:8080/v1/chat/completions

# Model name sent in API requests
model=claude-sonnet-4-20250514

# Max agentic loop iterations per user message
max_turns=20

# Max tokens per API response
max_tokens=8192

# Tool output caps (tune based on your context window size)
max_disasm_lines=1000
max_function_list=500
max_bytes_read=4096

# UI settings
font_size=13
dark_mode=true
```

### Environment variables

Environment variables override config file values:

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | API key (used for Claude backend) |
| `OPENAI_API_KEY` | API key (used for OpenAI backend) |
| `IDA_CHAT_BACKEND` | Backend selection: `claude` or `openai` |
| `IDA_CHAT_API_URL` | Custom API URL |

If no API key is found, a setup dialog will prompt you on first use.

### Using a local LLM

The plugin works with any local server that exposes an OpenAI-compatible `/v1/chat/completions` endpoint with tool/function calling support. Tested with [llama.cpp](https://github.com/ggerganov/llama.cpp) and [Ollama](https://ollama.com/).

Example setup with llama.cpp:

```bash
# Start llama.cpp server
llama-server -m qwen2.5-coder-7b.gguf --port 8080
```

Then configure the plugin:

```
backend=openai
api_url=http://localhost:8080/v1/chat/completions
model=qwen2.5-coder
```

Or via environment variables:

```bash
export IDA_CHAT_BACKEND=openai
export IDA_CHAT_API_URL=http://localhost:8080/v1/chat/completions
```

**Note:** The API key is optional for local backends. The quality of tool calling depends heavily on the model — larger models (14B+) with tool-use training tend to work best.

## Usage

1. Open IDA Pro with a binary
2. Press **Ctrl+Shift+C** to toggle the chat panel (or View menu)
3. Type a question and press Enter
4. The agent will use IDA SDK tools to analyze the binary and respond

### Deep Analyze

Click the **Deep Analyze** button (orange) to recursively analyze the function at the cursor position. The agent will:

1. Decompile the function and analyze its purpose
2. Rename the function if it has a generic name (e.g. `sub_401000`)
3. Set correct function prototype (return type, parameter types/names)
4. Rename all local variables to meaningful names
5. Detect struct patterns from fixed-offset pointer accesses and declare types
6. Add comments for complex logic
7. Recursively process all callees that aren't library/imported functions

This runs with a 100-turn limit and a specialized system prompt optimized for thorough annotation.

### Example queries

- "What functions are in this binary?"
- "Decompile the main function"
- "What references this function?" (with cursor on a function)
- "Find strings related to passwords"
- "Rename this function to `process_input`"

