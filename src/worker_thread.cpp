#include "worker_thread.h"
#include "api_client.h"
#include "tool_executor.h"
#include "tool_definitions.h"

#include <QMetaObject>
#include <QDebug>

namespace ida_chat {

const char* WorkerThread::ANALYSIS_LOOP_SYSTEM_PROMPT =
    "You are a reverse engineering expert embedded in IDA Pro. You will work continuously "
    "until stopped, analyzing one function at a time, depth-first through the call tree.\n\n"
    "## Procedure — repeat for each function\n\n"
    "1. `get_current_address` (first function only) or take the next callee from your queue\n"
    "2. `decompile` the function\n"
    "3. Read the code carefully. Determine what the function does and what part of the "
    "program it belongs to (e.g., networking, crypto, parsing, init, etc.)\n"
    "4. `rename_address` — pick a snake_case name that reflects its purpose. "
    "Use a short component prefix so related functions group together "
    "(e.g., `pkt_decrypt_payload`, `cfg_parse_entry`, `sess_validate_token`). "
    "Keep the prefix consistent: if the parent is `pkt_handle_incoming`, its helpers "
    "should also start with `pkt_` unless they clearly belong elsewhere.\n"
    "5. `set_function_type` — set the correct return type, parameter types, and "
    "meaningful parameter names\n"
    "6. `rename_local_variable` for EVERY auto-named variable (v1, v2, a1, a2…) — "
    "give each a descriptive snake_case name based on how it is used\n"
    "7. `set_local_variable_type` where IDA guessed wrong (e.g., `int` that is really "
    "a `char*`, or a void pointer that should be a struct pointer)\n"
    "8. Look for struct patterns — if a pointer is dereferenced at multiple fixed offsets "
    "(ptr->field_8, ptr->field_10, etc.), create a struct with `declare_type` and apply "
    "it with `set_local_variable_type`\n"
    "9. `set_decompiler_comment` on lines with non-obvious logic, magic numbers, or "
    "important operations. Use `line_addresses` from the decompile output for targeting.\n"
    "10. `decompile` again to verify your changes read well\n"
    "11. `get_callees` — add unnamed callees (sub_XXX/FUN_XXX) to your queue. "
    "Skip imports, library functions, and functions you already processed.\n"
    "12. Move to the next callee in your queue. When a callee's subtree is done, "
    "re-decompile the parent so the new names show up.\n\n"
    "## Rules\n\n"
    "- **Stay focused**: fully finish one function before moving to the next. "
    "Do not jump around.\n"
    "- **Depth-first**: go deep into the first callee, finish its subtree, then the next.\n"
    "- **Track processed functions**: keep a list of addresses you've done. Never redo one.\n"
    "- **Naming**: be specific and consistent. `decrypt_aes_block` beats `process_data`. "
    "Related functions share a prefix.\n"
    "- **Keep output short**: one line per function — what you renamed it to and why. "
    "No long explanations.\n\n"
    "Begin now.";

const char* WorkerThread::ANALYSIS_LOOP_CONTINUATION =
    "Continue. Process the next function in your queue. "
    "If the queue is empty, use `get_current_address` to check if the cursor moved "
    "to a new function and start from there.";

WorkerThread::WorkerThread(ToolExecutor* executor, const Config& config, QObject* parent)
    : QThread(parent)
    , executor_(executor)
    , config_(config)
    , conversation_history_(json::array())
{
}

WorkerThread::~WorkerThread() {
    cancel();
    wait();
}

void WorkerThread::send_message(const QString& message) {
    max_turns_override_ = -1;
    system_prompt_override_.clear();
    pending_message_ = message;
    start();
}

void WorkerThread::send_message(const QString& message, int max_turns_override,
                                const std::string& system_prompt_override,
                                bool loop_mode) {
    max_turns_override_ = max_turns_override;
    system_prompt_override_ = system_prompt_override;
    loop_mode_ = loop_mode;
    pending_message_ = message;
    start();
}

void WorkerThread::cancel() {
    if (client_) {
        client_->cancel();
    }
    requestInterruption();
}

void WorkerThread::clear_history() {
    conversation_history_ = json::array();
}

void WorkerThread::run() {
    // Create client in worker thread
    if (!client_) {
        client_ = std::make_unique<ApiClient>(
            config_.backend, config_.api_key,
            config_.effective_url(), config_.model);
    }
    client_->reset_cancel();

    const bool is_openai = config_.backend == Backend::OPENAI;

    // Determine effective max_turns and system prompt
    int max_turns = (max_turns_override_ > 0) ? max_turns_override_ : config_.max_turns;
    const char* system_prompt = system_prompt_override_.empty()
        ? SYSTEM_PROMPT : system_prompt_override_.c_str();

    // Add user message to history
    json user_msg;
    user_msg["role"] = "user";
    user_msg["content"] = pending_message_.toStdString();
    conversation_history_.push_back(user_msg);

    json tools = get_tool_definitions();

    // Agentic loop
    for (int turn = 0; turn < max_turns; turn++) {
        if (isInterruptionRequested()) {
            emit error_occurred("Cancelled");
            emit finished_processing();
            return;
        }

        emit thinking(true);

        // Send streaming request — emit text chunks as they arrive
        ApiResponse response = client_->send_request_streaming(
            conversation_history_,
            tools,
            system_prompt,
            config_.max_tokens,
            [this](const std::string& chunk) {
                emit text_chunk_received(QString::fromStdString(chunk));
            }
        );

        emit thinking(false);

        if (!response.success) {
            emit error_occurred(QString::fromStdString(response.error));
            // Remove the user message on error so user can retry
            if (!conversation_history_.empty()) {
                conversation_history_.erase(conversation_history_.end() - 1);
            }
            emit finished_processing();
            return;
        }

        // Parse normalized response (always Claude-shaped)
        const json& body = response.body;
        std::string stop_reason = body.value("stop_reason", "");
        const json& content = body["content"];

        // Store assistant message in conversation history (format differs per backend)
        if (is_openai) {
            // OpenAI format: {role:"assistant", content:"text", tool_calls:[...]}
            json assistant_msg;
            assistant_msg["role"] = "assistant";

            // Extract text and tool calls from normalized content
            std::string text_content;
            json tool_calls = json::array();
            for (const auto& block : content) {
                std::string type = block["type"].get<std::string>();
                if (type == "text") {
                    text_content += block["text"].get<std::string>();
                } else if (type == "tool_use") {
                    json tc;
                    tc["id"] = block["id"];
                    tc["type"] = "function";
                    tc["function"] = {
                        {"name", block["name"]},
                        {"arguments", block["input"].dump()}
                    };
                    tool_calls.push_back(tc);
                }
            }

            assistant_msg["content"] = text_content.empty() ? json(nullptr) : json(text_content);
            if (!tool_calls.empty()) {
                assistant_msg["tool_calls"] = tool_calls;
            }
            conversation_history_.push_back(assistant_msg);
        } else {
            // Claude format: {role:"assistant", content:[blocks]}
            json assistant_msg;
            assistant_msg["role"] = "assistant";
            assistant_msg["content"] = content;
            conversation_history_.push_back(assistant_msg);
        }

        // Process content blocks (emit signals, execute tools)
        bool has_tool_use = false;
        json tool_results_claude = json::array();  // For Claude backend
        // For OpenAI, we append individual tool messages after this loop

        struct ToolResult {
            std::string id;
            std::string name;
            std::string result;
        };
        std::vector<ToolResult> executed_tools;

        for (const auto& block : content) {
            std::string type = block["type"].get<std::string>();

            if (type == "text") {
                QString text = QString::fromStdString(block["text"].get<std::string>());
                emit text_received(text);
            }
            else if (type == "tool_use") {
                has_tool_use = true;
                std::string tool_name = block["name"].get<std::string>();
                std::string tool_id = block["id"].get<std::string>();
                json tool_input = block["input"];

                // Summarize the input for display
                QString input_summary = QString::fromStdString(tool_input.dump(2));
                if (input_summary.length() > 200) {
                    input_summary = input_summary.left(197) + "...";
                }
                emit tool_called(QString::fromStdString(tool_name), input_summary);

                // Execute tool on main thread via BlockingQueuedConnection
                QString result_str;
                QMetaObject::invokeMethod(
                    executor_,
                    "execute_tool",
                    Qt::BlockingQueuedConnection,
                    Q_ARG(QString, QString::fromStdString(tool_name)),
                    Q_ARG(QString, QString::fromStdString(tool_input.dump())),
                    Q_ARG(QString*, &result_str)
                );

                // Summary for display
                QString result_summary = result_str;
                if (result_summary.length() > 300) {
                    result_summary = result_summary.left(297) + "...";
                }
                emit tool_result_received(QString::fromStdString(tool_name), result_summary);

                executed_tools.push_back({tool_id, tool_name, result_str.toStdString()});

                if (!is_openai) {
                    // Build Claude-format tool result
                    json tool_result;
                    tool_result["type"] = "tool_result";
                    tool_result["tool_use_id"] = tool_id;
                    tool_result["content"] = result_str.toStdString();
                    tool_results_claude.push_back(tool_result);
                }
            }
        }

        // If there were tool calls, add tool results and continue loop
        if (has_tool_use && stop_reason == "tool_use") {
            if (is_openai) {
                // OpenAI: each tool result is a separate message with role:"tool"
                for (const auto& tr : executed_tools) {
                    json tool_msg;
                    tool_msg["role"] = "tool";
                    tool_msg["tool_call_id"] = tr.id;
                    tool_msg["content"] = tr.result;
                    conversation_history_.push_back(tool_msg);
                }
            } else {
                // Claude: single user message with all tool results
                json tool_msg;
                tool_msg["role"] = "user";
                tool_msg["content"] = tool_results_claude;
                conversation_history_.push_back(tool_msg);
            }
            continue;
        }

        // end_turn or no more tool calls
        if (loop_mode_ && !isInterruptionRequested()) {
            // Finalize current response block in UI before continuing
            emit response_complete();

            // Inject continuation message to keep the loop going
            json cont_msg;
            cont_msg["role"] = "user";
            cont_msg["content"] = std::string(ANALYSIS_LOOP_CONTINUATION);
            conversation_history_.push_back(cont_msg);
            continue;
        }
        break;
    }

    loop_mode_ = false;
    emit finished_processing();
}

} // namespace ida_chat
