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

// -------------------------------------------------------------------------
// Streaming SSE request
// -------------------------------------------------------------------------

struct StreamContext {
    std::string line_buffer;          // Buffer for incomplete SSE lines
    json accumulated_content;         // Build the content array as events arrive
    std::string accumulated_text;     // Full text accumulated across all text blocks
    std::string current_tool_id;      // ID of tool_use currently being streamed
    std::string current_tool_name;    // Name of tool currently being streamed
    std::string current_tool_args;    // Accumulated JSON arguments string
    std::string stop_reason;
    StreamCallback on_text_chunk;
    std::atomic<bool>* cancelled;
    Backend backend;

    StreamContext(StreamCallback cb, std::atomic<bool>* cancel_flag, Backend b)
        : accumulated_content(json::array())
        , on_text_chunk(std::move(cb))
        , cancelled(cancel_flag)
        , backend(b) {}

    void process_sse_line(const std::string& line) {
        if (line.empty() || line[0] == ':') return;  // Comment or empty

        if (line.substr(0, 6) != "data: ") return;
        std::string data = line.substr(6);

        if (data == "[DONE]") return;

        json event;
        try {
            event = json::parse(data);
        } catch (...) {
            return;
        }

        if (backend == Backend::OPENAI) {
            process_openai_event(event);
        } else {
            process_claude_event(event);
        }
    }

    void process_claude_event(const json& event) {
        std::string type = event.value("type", "");

        if (type == "content_block_start") {
            const auto& block = event["content_block"];
            std::string block_type = block.value("type", "");
            if (block_type == "tool_use") {
                current_tool_id = block.value("id", "");
                current_tool_name = block.value("name", "");
                current_tool_args.clear();
            }
        }
        else if (type == "content_block_delta") {
            const auto& delta = event["delta"];
            std::string delta_type = delta.value("type", "");
            if (delta_type == "text_delta") {
                std::string text = delta.value("text", "");
                if (!text.empty()) {
                    accumulated_text += text;
                    if (on_text_chunk) on_text_chunk(text);
                }
            }
            else if (delta_type == "input_json_delta") {
                current_tool_args += delta.value("partial_json", "");
            }
        }
        else if (type == "content_block_stop") {
            // Finalize current block
            if (!current_tool_id.empty()) {
                json tool_block;
                tool_block["type"] = "tool_use";
                tool_block["id"] = current_tool_id;
                tool_block["name"] = current_tool_name;
                try {
                    tool_block["input"] = json::parse(current_tool_args);
                } catch (...) {
                    tool_block["input"] = json::object();
                }
                accumulated_content.push_back(tool_block);
                current_tool_id.clear();
                current_tool_name.clear();
                current_tool_args.clear();
            }
        }
        else if (type == "message_delta") {
            if (event.contains("delta")) {
                stop_reason = event["delta"].value("stop_reason", "");
            }
        }
    }

    void process_openai_event(const json& event) {
        if (!event.contains("choices") || event["choices"].empty()) return;

        const auto& choice = event["choices"][0];
        const auto& delta = choice["delta"];

        // Text content
        if (delta.contains("content") && !delta["content"].is_null()) {
            std::string text = delta["content"].get<std::string>();
            if (!text.empty()) {
                accumulated_text += text;
                if (on_text_chunk) on_text_chunk(text);
            }
        }

        // Tool calls
        if (delta.contains("tool_calls")) {
            for (const auto& tc : delta["tool_calls"]) {
                if (tc.contains("id") && !tc["id"].get<std::string>().empty()) {
                    // New tool call starting
                    current_tool_id = tc["id"].get<std::string>();
                    if (tc.contains("function") && tc["function"].contains("name")) {
                        current_tool_name = tc["function"]["name"].get<std::string>();
                    }
                    current_tool_args.clear();
                }
                if (tc.contains("function") && tc["function"].contains("arguments")) {
                    current_tool_args += tc["function"]["arguments"].get<std::string>();
                }
            }
        }

        // Finish reason
        if (choice.contains("finish_reason") && !choice["finish_reason"].is_null()) {
            std::string fr = choice["finish_reason"].get<std::string>();
            if (fr == "tool_calls") {
                stop_reason = "tool_use";
            } else {
                stop_reason = "end_turn";
            }

            // Finalize any pending tool
            if (!current_tool_id.empty()) {
                json tool_block;
                tool_block["type"] = "tool_use";
                tool_block["id"] = current_tool_id;
                tool_block["name"] = current_tool_name;
                try {
                    tool_block["input"] = json::parse(current_tool_args);
                } catch (...) {
                    tool_block["input"] = json::object();
                }
                accumulated_content.push_back(tool_block);
                current_tool_id.clear();
                current_tool_name.clear();
                current_tool_args.clear();
            }
        }
    }

    ApiResponse build_response() {
        // Prepend accumulated text as a text block if any
        if (!accumulated_text.empty()) {
            json text_block;
            text_block["type"] = "text";
            text_block["text"] = accumulated_text;
            // Insert at beginning
            json final_content = json::array();
            final_content.push_back(text_block);
            for (const auto& item : accumulated_content) {
                final_content.push_back(item);
            }
            accumulated_content = final_content;
        }

        ApiResponse result;
        result.success = true;
        result.body["stop_reason"] = stop_reason.empty() ? "end_turn" : stop_reason;
        result.body["content"] = accumulated_content;
        return result;
    }
};

static size_t stream_write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* ctx = static_cast<StreamContext*>(userdata);
    if (ctx->cancelled->load()) return 0;

    size_t total = size * nmemb;
    ctx->line_buffer.append(ptr, total);

    // Process complete SSE lines (separated by \n)
    size_t pos;
    while ((pos = ctx->line_buffer.find('\n')) != std::string::npos) {
        std::string line = ctx->line_buffer.substr(0, pos);
        ctx->line_buffer.erase(0, pos + 1);

        // Remove trailing \r if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        ctx->process_sse_line(line);
    }

    return total;
}

ApiResponse ApiClient::send_request_streaming(const json& messages,
                                               const json& tools,
                                               const std::string& system,
                                               int max_tokens,
                                               StreamCallback on_text_chunk) {
    ApiResponse result;
    cancelled_.store(false);

    CURL* curl = curl_easy_init();
    if (!curl) {
        result.error = "Failed to initialize curl";
        return result;
    }

    // Build request body with stream: true
    std::string body_str;
    struct curl_slist* headers = nullptr;

    if (backend_ == Backend::OPENAI) {
        json request_body = build_openai_body(messages, tools, system, max_tokens);
        request_body["stream"] = true;
        body_str = request_body.dump();

        headers = curl_slist_append(headers, "content-type: application/json");
        if (!api_key_.empty()) {
            headers = curl_slist_append(headers, ("Authorization: Bearer " + api_key_).c_str());
        }
    } else {
        // Claude
        json request_body;
        request_body["model"] = model_;
        request_body["max_tokens"] = max_tokens;
        request_body["messages"] = messages;
        request_body["stream"] = true;
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

    StreamContext ctx(std::move(on_text_chunk), &cancelled_, backend_);

    curl_easy_setopt(curl, CURLOPT_URL, api_url_.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_str.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body_str.size()));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, stream_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);

    // Progress callback for cancellation
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, progress_callback);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &cancelled_);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);

    // Timeout: 10 minutes for long streaming responses
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 600L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);

    CURLcode res = curl_easy_perform(curl);

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    result.http_code = static_cast<int>(http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        if (cancelled_.load()) {
            result.error = "Request cancelled";
        } else {
            result.error = std::string("curl error: ") + curl_easy_strerror(res);
        }
        return result;
    }

    if (http_code != 200) {
        // For streaming errors, the response may be a JSON error object
        try {
            json err = json::parse(ctx.line_buffer);
            if (err.contains("error")) {
                if (err["error"].is_object() && err["error"].contains("message")) {
                    result.error = err["error"]["message"].get<std::string>();
                } else if (err["error"].is_string()) {
                    result.error = err["error"].get<std::string>();
                } else {
                    result.error = "HTTP " + std::to_string(http_code);
                }
            } else {
                result.error = "HTTP " + std::to_string(http_code);
            }
        } catch (...) {
            result.error = "HTTP " + std::to_string(http_code);
        }
        return result;
    }

    // Process any remaining data in the buffer
    if (!ctx.line_buffer.empty()) {
        ctx.process_sse_line(ctx.line_buffer);
    }

    return ctx.build_response();
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
