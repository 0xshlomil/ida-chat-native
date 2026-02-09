# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Native C++17 IDA Pro 9.x plugin that provides an AI-powered chat interface for reverse engineering. Uses Qt6 widgets for the UI and libcurl for HTTP. Supports Claude (Anthropic) and OpenAI-compatible API backends. The AI agent has access to 19 IDA SDK tools for binary analysis, decompilation, and IDB modification.

## Build Commands

```bash
# Build (auto-detects SDK from ../idasdk)
cmake -B build && cmake --build build

# Build with explicit SDK path
IDASDK=/path/to/idasdk/src cmake -B build && cmake --build build

# Install to IDA plugins directory
cp /path/to/idasdk/src/bin/plugins/ida-chat.so ~/.idapro/plugins/
```

Dependencies: `sudo apt install libcurl4-openssl-dev qt6-base-dev cmake build-essential`

No tests or linting are configured.

## Architecture

All code is in `src/` under the `ida_chat` namespace. JSON handling uses `nlohmann::json` (bundled in `third_party/`).

### Threading Model (critical to understand)

- **Main thread (Qt event loop):** UI (`ChatWidget`) and all IDA SDK calls (`ToolExecutor`). IDA's API is not thread-safe; all SDK interactions must happen here.
- **Worker thread (`WorkerThread`, extends `QThread`):** Runs the agentic loop — sends API requests, processes responses, dispatches tool calls back to main thread via `BlockingQueuedConnection`.

Tool execution flow: `WorkerThread` calls `ToolExecutor::execute_tool()` via `BlockingQueuedConnection` signal/slot, which blocks the worker thread while the main thread executes the IDA SDK call and writes the result.

### Core Components

| File | Role |
|------|------|
| `plugin.cpp/h` | IDA 9.x `plugmod_t` entry point, registers Ctrl+Shift+C action |
| `chat_widget.cpp/h` | Qt UI: chat display (QTextBrowser), input (QPlainTextEdit), settings dialog, markdown rendering, Catppuccin theming |
| `worker_thread.cpp/h` | Agentic loop: sends conversation + tools to API, handles tool_use responses, iterates up to max_turns |
| `api_client.cpp/h` | libcurl HTTP client, supports Claude and OpenAI formats, normalizes OpenAI responses to Claude content-block format |
| `tool_executor.cpp/h` | Dispatches tool calls to 19 IDA SDK wrapper methods, runs on main thread only |
| `tool_definitions.cpp/h` | JSON schemas for all tools (used in API requests) |
| `config.cpp/h` | Loads from `~/.idapro/ida-chat.conf` and env vars (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `IDA_CHAT_BACKEND`, `IDA_CHAT_API_URL`) |

### API Response Normalization

OpenAI responses are converted to Claude's content-block format (`{type: "text"|"tool_use", ...}`) so the agentic loop has a single code path regardless of backend.

### Address Parsing

`tool_executor.cpp` parses addresses flexibly: hex with prefix (`0x401000`), raw hex digits (`401000`), named addresses (`main`, `strlen`), and decimal fallback.
