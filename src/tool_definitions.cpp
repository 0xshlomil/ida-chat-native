#include "tool_definitions.h"

namespace ida_chat {

json get_tool_definitions() {
    return json::array({
        // 1. get_database_info
        {
            {"name", "get_database_info"},
            {"description", "Get general information about the loaded binary database including file name, processor, compiler, entry points, and segment count."},
            {"input_schema", {
                {"type", "object"},
                {"properties", json::object()},
                {"required", json::array()}
            }}
        },
        // 2. list_functions
        {
            {"name", "list_functions"},
            {"description", "List functions in the database. Returns function name, start address, and size. Use offset and limit for pagination."},
            {"input_schema", {
                {"type", "object"},
                {"properties", {
                    {"offset", {{"type", "integer"}, {"description", "Start index (default 0)"}}},
                    {"limit", {{"type", "integer"}, {"description", "Max functions to return (default 100, max 500)"}}},
                    {"filter", {{"type", "string"}, {"description", "Substring filter for function name (case-insensitive)"}}}
                }},
                {"required", json::array()}
            }}
        },
        // 3. get_function_info
        {
            {"name", "get_function_info"},
            {"description", "Get detailed information about a function: name, address range, size, flags, frame info, and local variables."},
            {"input_schema", {
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Function address as hex string (e.g. '0x401000') or function name"}}}
                }},
                {"required", json::array({"address"})}
            }}
        },
        // 4. get_disassembly
        {
            {"name", "get_disassembly"},
            {"description", "Get disassembly listing for an address range. Returns instruction address, bytes, mnemonic, and operands."},
            {"input_schema", {
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Start address as hex string (e.g. '0x401000') or function name"}}},
                    {"count", {{"type", "integer"}, {"description", "Number of instructions (default 30, max 200)"}}}
                }},
                {"required", json::array({"address"})}
            }}
        },
        // 5. decompile
        {
            {"name", "decompile"},
            {"description", "Decompile a function to pseudocode using Hex-Rays. Requires the decompiler plugin to be available."},
            {"input_schema", {
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Function address as hex string or function name"}}}
                }},
                {"required", json::array({"address"})}
            }}
        },
        // 6. get_xrefs_to
        {
            {"name", "get_xrefs_to"},
            {"description", "Get all cross-references TO an address (who references this address). Returns source address, type, and source function name."},
            {"input_schema", {
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Target address as hex string or name"}}},
                    {"limit", {{"type", "integer"}, {"description", "Max results (default 50)"}}}
                }},
                {"required", json::array({"address"})}
            }}
        },
        // 7. get_xrefs_from
        {
            {"name", "get_xrefs_from"},
            {"description", "Get all cross-references FROM an address (what does this address reference). Returns target address, type, and target name."},
            {"input_schema", {
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Source address as hex string or name"}}},
                    {"limit", {{"type", "integer"}, {"description", "Max results (default 50)"}}}
                }},
                {"required", json::array({"address"})}
            }}
        },
        // 8. get_strings
        {
            {"name", "get_strings"},
            {"description", "Get strings found in the binary. Returns address, length, type, and string content."},
            {"input_schema", {
                {"type", "object"},
                {"properties", {
                    {"offset", {{"type", "integer"}, {"description", "Start index (default 0)"}}},
                    {"limit", {{"type", "integer"}, {"description", "Max strings to return (default 100)"}}},
                    {"filter", {{"type", "string"}, {"description", "Substring filter (case-insensitive)"}}},
                    {"min_length", {{"type", "integer"}, {"description", "Minimum string length (default 4)"}}}
                }},
                {"required", json::array()}
            }}
        },
        // 9. list_segments
        {
            {"name", "list_segments"},
            {"description", "List all segments (sections) in the binary with name, address range, size, permissions, and type."},
            {"input_schema", {
                {"type", "object"},
                {"properties", json::object()},
                {"required", json::array()}
            }}
        },
        // 10. get_bytes
        {
            {"name", "get_bytes"},
            {"description", "Read raw bytes from the database at a given address. Returns hex-encoded bytes."},
            {"input_schema", {
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Start address as hex string"}}},
                    {"size", {{"type", "integer"}, {"description", "Number of bytes to read (default 64, max 4096)"}}}
                }},
                {"required", json::array({"address"})}
            }}
        },
        // 11. search_bytes
        {
            {"name", "search_bytes"},
            {"description", "Search for a byte pattern in the database. Pattern is hex with optional wildcards (e.g. '48 8B ? ? 90'). '?' matches any byte."},
            {"input_schema", {
                {"type", "object"},
                {"properties", {
                    {"pattern", {{"type", "string"}, {"description", "Hex byte pattern with optional '?' wildcards"}}},
                    {"start_address", {{"type", "string"}, {"description", "Start address for search (default: beginning of first segment)"}}},
                    {"limit", {{"type", "integer"}, {"description", "Max results (default 10)"}}}
                }},
                {"required", json::array({"pattern"})}
            }}
        },
        // 12. get_names
        {
            {"name", "get_names"},
            {"description", "List named locations (labels, imports, exports) in the database."},
            {"input_schema", {
                {"type", "object"},
                {"properties", {
                    {"offset", {{"type", "integer"}, {"description", "Start index (default 0)"}}},
                    {"limit", {{"type", "integer"}, {"description", "Max names to return (default 100)"}}},
                    {"filter", {{"type", "string"}, {"description", "Substring filter (case-insensitive)"}}}
                }},
                {"required", json::array()}
            }}
        },
        // 13. rename_address
        {
            {"name", "rename_address"},
            {"description", "Rename a location (function or label) at the given address."},
            {"input_schema", {
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Address as hex string"}}},
                    {"new_name", {{"type", "string"}, {"description", "New name for the location"}}}
                }},
                {"required", json::array({"address", "new_name"})}
            }}
        },
        // 14. set_comment
        {
            {"name", "set_comment"},
            {"description", "Set a comment at an address. Can be a regular (line) comment or a repeatable comment."},
            {"input_schema", {
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Address as hex string"}}},
                    {"comment", {{"type", "string"}, {"description", "Comment text"}}},
                    {"repeatable", {{"type", "boolean"}, {"description", "If true, set as repeatable comment (default false)"}}}
                }},
                {"required", json::array({"address", "comment"})}
            }}
        },
        // 15. get_current_address
        {
            {"name", "get_current_address"},
            {"description", "Get the current cursor address in IDA's disassembly view. Use this when the user says 'this function', 'here', or 'current address'."},
            {"input_schema", {
                {"type", "object"},
                {"properties", json::object()},
                {"required", json::array()}
            }}
        },
        // 16. jump_to_address
        {
            {"name", "jump_to_address"},
            {"description", "Navigate IDA's disassembly view to the specified address."},
            {"input_schema", {
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Target address as hex string or name"}}}
                }},
                {"required", json::array({"address"})}
            }}
        },
        // 17. rename_local_variable
        {
            {"name", "rename_local_variable"},
            {"description", "Rename a local variable or parameter in the decompiled pseudocode of a function. Requires the Hex-Rays decompiler. Use 'decompile' first to see current variable names."},
            {"input_schema", {
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Function address as hex string or function name"}}},
                    {"old_name", {{"type", "string"}, {"description", "Current name of the variable to rename"}}},
                    {"new_name", {{"type", "string"}, {"description", "New name for the variable"}}}
                }},
                {"required", json::array({"address", "old_name", "new_name"})}
            }}
        },
        // 18. set_decompiler_comment
        {
            {"name", "set_decompiler_comment"},
            {"description", "Set a comment on a line in the decompiled pseudocode. The comment appears in the Hex-Rays pseudocode view. Use 'decompile' first to identify the correct address for the line you want to comment."},
            {"input_schema", {
                {"type", "object"},
                {"properties", {
                    {"function_address", {{"type", "string"}, {"description", "Function address as hex string or function name (the function containing the line)"}}},
                    {"address", {{"type", "string"}, {"description", "Address of the pseudocode line to comment (from the decompiled output)"}}},
                    {"comment", {{"type", "string"}, {"description", "Comment text to set"}}}
                }},
                {"required", json::array({"function_address", "address", "comment"})}
            }}
        },
        // 19. set_local_variable_type
        {
            {"name", "set_local_variable_type"},
            {"description", "Change the type of a local variable or parameter in the decompiled pseudocode. Requires the Hex-Rays decompiler. Use 'decompile' first to see current variable names and types."},
            {"input_schema", {
                {"type", "object"},
                {"properties", {
                    {"address", {{"type", "string"}, {"description", "Function address as hex string or function name"}}},
                    {"variable_name", {{"type", "string"}, {"description", "Name of the variable to retype"}}},
                    {"new_type", {{"type", "string"}, {"description", "New C type for the variable (e.g. 'int *', 'char[256]', 'struct sockaddr *')"}}}
                }},
                {"required", json::array({"address", "variable_name", "new_type"})}
            }}
        }
    });
}

} // namespace ida_chat
