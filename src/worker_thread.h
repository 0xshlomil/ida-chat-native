#pragma once

#include <QThread>
#include <QString>
#include <memory>
#include <nlohmann/json.hpp>

#include "config.h"

namespace ida_chat {

using json = nlohmann::json;

class ApiClient;
class ToolExecutor;

class WorkerThread : public QThread {
    Q_OBJECT

public:
    explicit WorkerThread(ToolExecutor* executor, const Config& config, QObject* parent = nullptr);
    ~WorkerThread() override;

    // Start processing a user message
    void send_message(const QString& message);

    // Cancel the current operation
    void cancel();

    // Clear conversation history
    void clear_history();

signals:
    // Emitted when text content is received from the assistant
    void text_received(const QString& text);

    // Emitted when a tool is called (for display in chat)
    void tool_called(const QString& tool_name, const QString& input_summary);

    // Emitted when tool execution completes
    void tool_result_received(const QString& tool_name, const QString& result_summary);

    // Emitted when the agent is thinking/processing
    void thinking(bool is_thinking);

    // Emitted on error
    void error_occurred(const QString& error);

    // Emitted when the full agentic loop is done
    void finished_processing();

protected:
    void run() override;

private:
    ToolExecutor* executor_;  // Owned by main thread
    Config config_;
    QString pending_message_;
    json conversation_history_;
    std::unique_ptr<ApiClient> client_;

    // System prompt
    static constexpr const char* SYSTEM_PROMPT =
        "You are a reverse engineering assistant embedded in IDA Pro. "
        "Use the provided tools to analyze the binary and answer the user's questions.\n\n"
        "When the user says \"this function\", \"here\", or \"current address\", "
        "use get_current_address first to find where the cursor is.\n\n"
        "Use get_database_info to understand the binary before deep analysis. "
        "Combine multiple tools for thorough analysis. "
        "When asked to decompile, show the pseudocode in a code block.\n\n"
        "You can modify the database to help the user understand the binary:\n"
        "- Use rename_address to rename functions and labels\n"
        "- Use rename_local_variable to rename variables in decompiled pseudocode\n"
        "- Use set_local_variable_type to change variable types in pseudocode\n"
        "- Use set_comment to add disassembly comments\n"
        "- Use set_decompiler_comment to add pseudocode comments\n\n"
        "When the user asks you to annotate, rename, or clean up code, "
        "decompile first to see current names, then apply renames and comments. "
        "Use meaningful names based on your analysis of the code's behavior.\n\n"
        "Be concise but thorough. Format your responses with markdown.";
};

} // namespace ida_chat
