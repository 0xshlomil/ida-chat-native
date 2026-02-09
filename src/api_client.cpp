#include "api_client.h"

#include <curl/curl.h>
#include <cstring>

namespace ida_chat {

static size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* response = static_cast<std::string*>(userdata);
    response->append(ptr, size * nmemb);
    return size * nmemb;
}

static int progress_callback(void* clientp, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
    auto* cancelled = static_cast<std::atomic<bool>*>(clientp);
    return cancelled->load() ? 1 : 0;
}

ApiClient::ApiClient(Backend backend, const std::string& api_key,
                     const std::string& api_url, const std::string& model)
    : backend_(backend), api_key_(api_key), api_url_(api_url), model_(model) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

ApiClient::~ApiClient() {
    curl_global_cleanup();
}

// -------------------------------------------------------------------------
// OpenAI format conversion helpers
// -------------------------------------------------------------------------

json ApiClient::convert_tools_to_openai(const json& claude_tools) {
    // Claude: [{name, description, input_schema}]
    // OpenAI: [{type:"function", function:{name, description, parameters}}]
    json openai_tools = json::array();
    for (const auto& tool : claude_tools) {
        json fn;
        fn["name"] = tool["name"];
        fn["description"] = tool["description"];
        fn["parameters"] = tool["input_schema"];
        openai_tools.push_back({{"type", "function"}, {"function", fn}});
    }
    return openai_tools;
}

json ApiClient::build_openai_body(const json& messages, const json& tools,
                                  const std::string& system, int max_tokens) {
    json body;
    body["model"] = model_;
    body["max_tokens"] = max_tokens;

    // OpenAI: system prompt is a message, not a top-level field
    json msgs = json::array();
    if (!system.empty()) {
        msgs.push_back({{"role", "system"}, {"content", system}});
    }
    for (const auto& msg : messages) {
        msgs.push_back(msg);
    }
    body["messages"] = msgs;

    if (!tools.empty()) {
        body["tools"] = convert_tools_to_openai(tools);
    }

    return body;
}

ApiResponse ApiClient::normalize_openai_response(const json& openai_body) {
    // Convert OpenAI response to Claude-shaped body:
    // { stop_reason: "end_turn"|"tool_use", content: [{type:"text",text:"..."},...] }
    ApiResponse result;
    result.success = true;

    if (!openai_body.contains("choices") || openai_body["choices"].empty()) {
        result.success = false;
        result.error = "No choices in OpenAI response";
        return result;
    }

    const auto& choice = openai_body["choices"][0];
    const auto& message = choice["message"];
    std::string finish_reason = choice.value("finish_reason", "stop");

    json normalized;
    json content = json::array();

    // Text content
    if (message.contains("content") && !message["content"].is_null()) {
        std::string text = message["content"].get<std::string>();
        if (!text.empty()) {
            content.push_back({{"type", "text"}, {"text", text}});
        }
    }

    // Tool calls
    if (message.contains("tool_calls") && !message["tool_calls"].is_null()) {
        for (const auto& tc : message["tool_calls"]) {
            json tool_use;
            tool_use["type"] = "tool_use";
            tool_use["id"] = tc["id"];
            tool_use["name"] = tc["function"]["name"];

            // Parse the arguments string into JSON
            std::string args_str = tc["function"]["arguments"].get<std::string>();
            try {
                tool_use["input"] = json::parse(args_str);
            } catch (...) {
                tool_use["input"] = json::object();
            }
            content.push_back(tool_use);
        }
    }

    // Map finish_reason
    if (finish_reason == "tool_calls") {
        normalized["stop_reason"] = "tool_use";
    } else {
        normalized["stop_reason"] = "end_turn";
    }

    normalized["content"] = content;
    result.body = normalized;
    return result;
}

// -------------------------------------------------------------------------
// Main send_request
// -------------------------------------------------------------------------

ApiResponse ApiClient::send_request(const json& messages,
                                    const json& tools,
                                    const std::string& system,
                                    int max_tokens) {
    ApiResponse result;
    cancelled_.store(false);

    CURL* curl = curl_easy_init();
    if (!curl) {
        result.error = "Failed to initialize curl";
        return result;
    }

    // Build request body and headers based on backend
    std::string body_str;
    struct curl_slist* headers = nullptr;

    if (backend_ == Backend::OPENAI) {
        json request_body = build_openai_body(messages, tools, system, max_tokens);
        body_str = request_body.dump();

        headers = curl_slist_append(headers, "content-type: application/json");
        if (!api_key_.empty()) {
            headers = curl_slist_append(headers, ("Authorization: Bearer " + api_key_).c_str());
        }
    } else {
        // Claude (default)
        json request_body;
        request_body["model"] = model_;
        request_body["max_tokens"] = max_tokens;
        request_body["messages"] = messages;
        if (!system.empty()) {
            request_body["system"] = system;
        }
        if (!tools.empty()) {
            request_body["tools"] = tools;
        }
        body_str = request_body.dump();

        headers = curl_slist_append(headers, ("x-api-key: " + api_key_).c_str());
        headers = curl_slist_append(headers, "anthropic-version: 2023-06-01");
        headers = curl_slist_append(headers, "content-type: application/json");
    }

    std::string response_str;

    curl_easy_setopt(curl, CURLOPT_URL, api_url_.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_str.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body_str.size()));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_str);

    // Progress callback for cancellation
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, progress_callback);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &cancelled_);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);

    // Timeout: 5 minutes for long responses
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        if (cancelled_.load()) {
            result.error = "Request cancelled";
        } else {
            result.error = std::string("curl error: ") + curl_easy_strerror(res);
        }
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return result;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    result.http_code = static_cast<int>(http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    // Parse response JSON
    json response_json;
    try {
        response_json = json::parse(response_str);
    } catch (const json::parse_error& e) {
        result.error = std::string("JSON parse error: ") + e.what();
        return result;
    }

    if (http_code != 200) {
        // Try to extract error message
        if (response_json.contains("error")) {
            if (response_json["error"].is_object() && response_json["error"].contains("message")) {
                result.error = response_json["error"]["message"].get<std::string>();
            } else if (response_json["error"].is_string()) {
                result.error = response_json["error"].get<std::string>();
            } else {
                result.error = "HTTP " + std::to_string(http_code);
            }
        } else {
            result.error = "HTTP " + std::to_string(http_code);
        }
        return result;
    }

    // Backend-specific response normalization
    if (backend_ == Backend::OPENAI) {
        return normalize_openai_response(response_json);
    }

    // Claude response: already in the expected shape
    result.success = true;
    result.body = response_json;
    return result;
}

void ApiClient::cancel() {
    cancelled_.store(true);
}

bool ApiClient::is_cancelled() const {
    return cancelled_.load();
}

void ApiClient::reset_cancel() {
    cancelled_.store(false);
}

} // namespace ida_chat
