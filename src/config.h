#pragma once

#include <string>

namespace ida_chat {

enum class Backend { CLAUDE, OPENAI };

struct Theme {
    const char* base;      // main background
    const char* mantle;    // widget background
    const char* surface0;  // input bg, borders
    const char* surface1;  // borders, dim bg
    const char* surface2;  // hover
    const char* overlay0;  // subtle text
    const char* text;      // main text
    const char* subtext;   // secondary text
    const char* blue;      // accent
    const char* sapphire;  // hover accent
    const char* green;     // success
    const char* red;       // error
    const char* peach;     // processing
    const char* pink;      // cancel hover
};

Theme get_theme(bool dark_mode);

struct Config {
    Backend backend = Backend::CLAUDE;
    std::string api_key;
    std::string api_url;  // Empty = use default for backend
    std::string model = "claude-sonnet-4-20250514";
    int max_turns = 20;
    int max_tokens = 8192;
    int max_disasm_lines = 1000;    // cap for get_disassembly tool
    int max_function_list = 500;    // cap for list_functions tool
    int max_bytes_read = 4096;      // cap for get_bytes tool
    int font_size = 13;             // base font size in px
    bool dark_mode = true;  // true = Catppuccin Mocha, false = Catppuccin Latte

    // Returns the effective API URL (default if api_url is empty)
    std::string effective_url() const {
        if (!api_url.empty()) return api_url;
        if (backend == Backend::OPENAI)
            return "http://localhost:8080/v1/chat/completions";
        return "https://api.anthropic.com/v1/messages";
    }
};

// Load config: env vars, then ~/.idapro/ida-chat.conf
Config load_config();

// Save full config to ~/.idapro/ida-chat.conf
void save_config(const Config& cfg);

// Returns themed stylesheet for the setup dialog
std::string get_dialog_style(const Theme& t);

// Show setup dialog. Fills cfg and returns true if accepted.
bool show_setup_dialog(Config& cfg);

} // namespace ida_chat
