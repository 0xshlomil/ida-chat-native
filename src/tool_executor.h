#pragma once

#include <string>
#include <QObject>
#include <nlohmann/json.hpp>

#include "config.h"

namespace ida_chat {

using json = nlohmann::json;

// Executes IDA SDK tool calls on the main thread.
// Must be created on the main thread so slots run there via BlockingQueuedConnection.
class ToolExecutor : public QObject {
    Q_OBJECT

public:
    explicit ToolExecutor(const Config& config, QObject* parent = nullptr);

    // Update config (e.g. after settings change)
    void update_config(const Config& config) { config_ = config; }

    // Check if decompiler is available
    bool has_decompiler() const { return has_decompiler_; }

public slots:
    // Execute a tool call. Called via BlockingQueuedConnection from worker thread.
    // tool_name: name of the tool to execute
    // input: JSON input parameters
    // result: output JSON result string (written by this method)
    void execute_tool(const QString& tool_name, const QString& input, QString* result);

private:
    Config config_;
    bool has_decompiler_ = false;

    // Individual tool implementations
    json tool_get_database_info(const json& input);
    json tool_list_functions(const json& input);
    json tool_get_function_info(const json& input);
    json tool_get_disassembly(const json& input);
    json tool_decompile(const json& input);
    json tool_get_xrefs_to(const json& input);
    json tool_get_xrefs_from(const json& input);
    json tool_get_strings(const json& input);
    json tool_list_segments(const json& input);
    json tool_get_bytes(const json& input);
    json tool_search_bytes(const json& input);
    json tool_get_names(const json& input);
    json tool_rename_address(const json& input);
    json tool_set_comment(const json& input);
    json tool_get_current_address(const json& input);
    json tool_jump_to_address(const json& input);
    json tool_rename_local_variable(const json& input);
    json tool_set_decompiler_comment(const json& input);
    json tool_set_local_variable_type(const json& input);
    json tool_list_imports(const json& input);
    json tool_get_callees(const json& input);
    json tool_get_basic_blocks(const json& input);
    json tool_get_callgraph(const json& input);
    json tool_set_function_type(const json& input);
    json tool_declare_type(const json& input);
    json tool_define_function(const json& input);
    json tool_get_stack_frame(const json& input);
};

} // namespace ida_chat
