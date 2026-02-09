#pragma once

#include <nlohmann/json.hpp>

namespace ida_chat {

using json = nlohmann::json;

// Returns the JSON array of all 19 tool definitions for the Claude API
json get_tool_definitions();

} // namespace ida_chat
