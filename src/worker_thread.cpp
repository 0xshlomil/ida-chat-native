#include "worker_thread.h"
#include "api_client.h"
#include "tool_executor.h"
#include "tool_definitions.h"

#include <QMetaObject>
#include <QDebug>

namespace ida_chat {

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

    // Add user message to history
    json user_msg;
    user_msg["role"] = "user";
    user_msg["content"] = pending_message_.toStdString();
    conversation_history_.push_back(user_msg);

    json tools = get_tool_definitions();

    // Agentic loop
    for (int turn = 0; turn < config_.max_turns; turn++) {
        if (isInterruptionRequested()) {
            emit error_occurred("Cancelled");
            emit finished_processing();
            return;
        }

        emit thinking(true);

        // Send request (response body is always normalized to Claude shape)
        ApiResponse response = client_->send_request(
            conversation_history_,
            tools,
            SYSTEM_PROMPT,
            config_.max_tokens
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

        // end_turn or no more tool calls: done
        break;
    }

    emit finished_processing();
}

} // namespace ida_chat
