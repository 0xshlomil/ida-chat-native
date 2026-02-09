#pragma once

#include <string>
#include <atomic>
#include <nlohmann/json.hpp>

#include "config.h"

namespace ida_chat {

using json = nlohmann::json;

struct ApiResponse {
    bool success = false;
    json body;           // Normalized response (always Claude-shaped)
    std::string error;   // Error message if !success
    int http_code = 0;
};

class ApiClient {
public:
    ApiClient(Backend backend, const std::string& api_key,
              const std::string& api_url, const std::string& model);
    ~ApiClient();

    // Send a request. Blocking call.
    // messages: array of message objects (in the backend's native format)
    // tools: array of tool definitions (Claude format — converted internally for OpenAI)
    // system: system prompt string
    // Returns normalized response with Claude-shaped body
    ApiResponse send_request(const json& messages,
                             const json& tools,
                             const std::string& system,
                             int max_tokens);

    Backend backend() const { return backend_; }

    void cancel();
    bool is_cancelled() const;
    void reset_cancel();

private:
    Backend backend_;
    std::string api_key_;
    std::string api_url_;
    std::string model_;
    std::atomic<bool> cancelled_{false};

    // OpenAI format helpers
    json build_openai_body(const json& messages, const json& tools,
                           const std::string& system, int max_tokens);
    json convert_tools_to_openai(const json& claude_tools);
    ApiResponse normalize_openai_response(const json& openai_body);
};

} // namespace ida_chat
