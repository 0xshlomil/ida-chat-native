#include "tool_executor.h"

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <funcs.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <xref.hpp>
#include <segment.hpp>
#include <auto.hpp>
#include <kernwin.hpp>
#include <frame.hpp>
#include <ua.hpp>
#include <search.hpp>
#include <strlist.hpp>
#include <entry.hpp>
#include <nalt.hpp>
#include <typeinf.hpp>
#include <gdl.hpp>

// Hex-Rays decompiler (optional)
// Qt defines 'emit' as a macro which conflicts with hexrays codegen_t::emit()
#pragma push_macro("emit")
#undef emit
#include <hexrays.hpp>
#pragma pop_macro("emit")

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <set>
#include <map>
#include <queue>

namespace ida_chat {

// Helper: parse an address from hex string or name
static ea_t parse_address(const std::string& addr_str) {
    if (addr_str.empty()) return BADADDR;

    // Try as hex number (with or without 0x prefix)
    if (addr_str.size() >= 2 && (addr_str[0] == '0' && (addr_str[1] == 'x' || addr_str[1] == 'X'))) {
        return static_cast<ea_t>(std::stoull(addr_str, nullptr, 16));
    }

    // Try as pure hex digits
    bool all_hex = std::all_of(addr_str.begin(), addr_str.end(), [](char c) {
        return std::isxdigit(static_cast<unsigned char>(c));
    });
    if (all_hex && addr_str.size() >= 4) {
        return static_cast<ea_t>(std::stoull(addr_str, nullptr, 16));
    }

    // Try as name
    ea_t ea = get_name_ea(BADADDR, addr_str.c_str());
    if (ea != BADADDR) return ea;

    // Last resort: try as decimal
    try {
        return static_cast<ea_t>(std::stoull(addr_str, nullptr, 0));
    } catch (...) {
        return BADADDR;
    }
}

// Helper: format address as hex string
static std::string hex_addr(ea_t ea) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::setfill('0') << std::setw(sizeof(ea_t) * 2) << ea;
    return ss.str();
}

// Helper: get name at address (or empty)
static std::string get_name_at(ea_t ea) {
    qstring name;
    if (get_name(&name, ea) && !name.empty()) {
        return std::string(name.c_str());
    }
    return {};
}

// Helper: get xref type name
static const char* xref_type_name(char type) {
    switch (type) {
        case fl_CF: return "call_far";
        case fl_CN: return "call_near";
        case fl_JF: return "jump_far";
        case fl_JN: return "jump_near";
        case fl_F:  return "flow";
        case dr_O:  return "data_offset";
        case dr_W:  return "data_write";
        case dr_R:  return "data_read";
        default:    return "unknown";
    }
}

ToolExecutor::ToolExecutor(const Config& config, QObject* parent) : QObject(parent), config_(config) {
    // Check if Hex-Rays decompiler is available
    has_decompiler_ = init_hexrays_plugin();
}

bool ToolExecutor::ensure_decompiler() {
    if (has_decompiler_)
        return true;

    // Try standard init (works if local decompiler is already loaded)
    has_decompiler_ = init_hexrays_plugin();
    if (has_decompiler_) {
        msg("[ida-chat] Decompiler: init_hexrays_plugin() succeeded\n");
        return true;
    }
    msg("[ida-chat] Decompiler: init_hexrays_plugin() failed, hexdsp=%p\n", get_hexdsp());

    // Dump all registered plugins for diagnostics
    msg("[ida-chat] Registered plugins:\n");
    for (plugin_info_t* pi = get_plugins(); pi != nullptr; pi = pi->next) {
        msg("[ida-chat]   name='%s' path='%s' loaded=%s\n",
            pi->name ? pi->name : "(null)",
            pi->path ? pi->path : "(null)",
            pi->entry ? "yes" : "no");
    }

    // Force-load the decompiler plugin — covers cloud (hexcx*) and local (hexx*)
    // variants across architectures. The cloud decompiler in IDA Free/Home
    // loads late, so it may not be available during our plugin's init().
    static const char* decompiler_plugins[] = {
        "hexcx64", "hexcx86",                        // cloud x86
        "hexcarm64", "hexcarm",                       // cloud ARM
        "hexcmips64", "hexcmips",                     // cloud MIPS
        "hexcppc64", "hexcppc",                       // cloud PPC
        "hexcrv64",                                   // cloud RISC-V
        "hexx64", "hexarm64", "hexarm",               // local
        "hexmips64", "hexmips", "hexppc64", "hexppc",
        "hexrv64",
        nullptr
    };
    for (const char** p = decompiler_plugins; *p; ++p) {
        plugin_t* found = find_plugin(*p, false);
        if (found != nullptr) {
            msg("[ida-chat] Found plugin '%s', loading...\n", *p);
            load_plugin(*p);
            has_decompiler_ = init_hexrays_plugin();
            if (has_decompiler_) {
                msg("[ida-chat] Decompiler available after loading '%s'\n", *p);
                return true;
            }
            msg("[ida-chat] init_hexrays_plugin() still false after loading '%s'\n", *p);
        }
    }

    // Try scanning registered plugins for any hex-rays variant
    for (plugin_info_t* pi = get_plugins(); pi != nullptr; pi = pi->next) {
        if (pi->path != nullptr && strstr(pi->path, "hex") != nullptr) {
            msg("[ida-chat] Trying hex plugin: name='%s' path='%s'\n",
                pi->name ? pi->name : "(null)", pi->path);
            if (pi->entry == nullptr) {
                invoke_plugin(pi);
                has_decompiler_ = init_hexrays_plugin();
                if (has_decompiler_) {
                    msg("[ida-chat] Decompiler available after invoking '%s'\n", pi->name);
                    return true;
                }
            } else {
                msg("[ida-chat]   Already loaded, hexdsp=%p\n", get_hexdsp());
            }
        }
    }

    // Check if hexdsp became available through any of the above
    if (get_hexdsp() != nullptr) {
        msg("[ida-chat] hexdsp became available: %p\n", get_hexdsp());
        has_decompiler_ = true;
    } else {
        msg("[ida-chat] Decompiler NOT available. hexdsp=null\n");
    }

    return has_decompiler_;
}

void ToolExecutor::execute_tool(const QString& tool_name, const QString& input, QString* result) {
    json input_json;
    try {
        input_json = json::parse(input.toStdString());
    } catch (...) {
        input_json = json::object();
    }

    // Suppress IDA dialog boxes during tool execution so the agent
    // is never blocked waiting for user confirmation.
    bool old_batch = batch;
    batch = true;

    json output;
    std::string name = tool_name.toStdString();

    try {
        if (name == "get_database_info") output = tool_get_database_info(input_json);
        else if (name == "list_functions") output = tool_list_functions(input_json);
        else if (name == "get_function_info") output = tool_get_function_info(input_json);
        else if (name == "get_disassembly") output = tool_get_disassembly(input_json);
        else if (name == "decompile") output = tool_decompile(input_json);
        else if (name == "get_xrefs_to") output = tool_get_xrefs_to(input_json);
        else if (name == "get_xrefs_from") output = tool_get_xrefs_from(input_json);
        else if (name == "get_strings") output = tool_get_strings(input_json);
        else if (name == "list_segments") output = tool_list_segments(input_json);
        else if (name == "get_bytes") output = tool_get_bytes(input_json);
        else if (name == "search_bytes") output = tool_search_bytes(input_json);
        else if (name == "get_names") output = tool_get_names(input_json);
        else if (name == "rename_address") output = tool_rename_address(input_json);
        else if (name == "set_comment") output = tool_set_comment(input_json);
        else if (name == "get_current_address") output = tool_get_current_address(input_json);
        else if (name == "jump_to_address") output = tool_jump_to_address(input_json);
        else if (name == "rename_local_variable") output = tool_rename_local_variable(input_json);
        else if (name == "set_decompiler_comment") output = tool_set_decompiler_comment(input_json);
        else if (name == "set_local_variable_type") output = tool_set_local_variable_type(input_json);
        else if (name == "list_imports") output = tool_list_imports(input_json);
        else if (name == "get_callees") output = tool_get_callees(input_json);
        else if (name == "get_basic_blocks") output = tool_get_basic_blocks(input_json);
        else if (name == "get_callgraph") output = tool_get_callgraph(input_json);
        else if (name == "set_function_type") output = tool_set_function_type(input_json);
        else if (name == "declare_type") output = tool_declare_type(input_json);
        else if (name == "define_function") output = tool_define_function(input_json);
        else if (name == "get_stack_frame") output = tool_get_stack_frame(input_json);
        else {
            output = {{"error", "Unknown tool: " + name}};
        }
    } catch (const std::exception& e) {
        output = {{"error", std::string("Tool execution error: ") + e.what()}};
    }

    batch = old_batch;
    *result = QString::fromStdString(output.dump());
}

json ToolExecutor::tool_get_database_info(const json&) {
    json info;
    // File path
    char filepath[QMAXPATH];
    get_input_file_path(filepath, sizeof(filepath));
    info["file_path"] = filepath;

    // Input file MD5
    uchar md5[16];
    if (retrieve_input_file_md5(md5)) {
        std::ostringstream ss;
        for (int i = 0; i < 16; i++)
            ss << std::hex << std::setfill('0') << std::setw(2) << (int)md5[i];
        info["md5"] = ss.str();
    }

    // Processor
    info["processor"] = inf_get_procname().c_str();

    // File type
    info["file_type"] = static_cast<int>(inf_get_filetype());

    // Bits
    info["bits"] = static_cast<int>(inf_get_app_bitness());

    // Entry points
    json entries = json::array();
    size_t n_entries = get_entry_qty();
    for (size_t i = 0; i < n_entries && i < 20; i++) {
        uval_t ord = get_entry_ordinal(static_cast<int>(i));
        ea_t ea = get_entry(ord);
        json entry;
        entry["address"] = hex_addr(ea);
        qstring ename;
        if (get_entry_name(&ename, ord))
            entry["name"] = ename.c_str();
        entries.push_back(entry);
    }
    info["entry_points"] = entries;

    // Counts
    info["function_count"] = static_cast<int>(get_func_qty());
    info["segment_count"] = static_cast<int>(get_segm_qty());
    // Always report decompiler as available — modern IDA versions all have
    // some form of decompiler (local or cloud). Let the actual decompile
    // tool call produce a real error if it truly isn't available, rather
    // than telling the LLM not to try.
    ensure_decompiler();
    info["has_decompiler"] = true;

    return info;
}

json ToolExecutor::tool_list_functions(const json& input) {
    int offset = input.value("offset", 0);
    int limit = std::min(input.value("limit", 100), config_.max_function_list);
    std::string filter = input.value("filter", "");

    // Convert filter to lowercase
    std::string filter_lower = filter;
    std::transform(filter_lower.begin(), filter_lower.end(), filter_lower.begin(), ::tolower);

    json functions = json::array();
    int total = static_cast<int>(get_func_qty());
    int count = 0;
    int skipped = 0;

    for (int i = 0; i < total && count < limit; i++) {
        func_t* func = getn_func(i);
        if (!func) continue;

        qstring fname;
        get_func_name(&fname, func->start_ea);
        std::string name_str = fname.c_str();

        // Apply filter
        if (!filter_lower.empty()) {
            std::string name_lower = name_str;
            std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
            if (name_lower.find(filter_lower) == std::string::npos)
                continue;
        }

        if (skipped < offset) {
            skipped++;
            continue;
        }

        json f;
        f["name"] = name_str;
        f["address"] = hex_addr(func->start_ea);
        f["size"] = static_cast<int64_t>(func->size());
        functions.push_back(f);
        count++;
    }

    json result;
    result["functions"] = functions;
    result["total"] = total;
    result["offset"] = offset;
    result["count"] = count;
    return result;
}

json ToolExecutor::tool_get_function_info(const json& input) {
    std::string addr_str = input.at("address").get<std::string>();
    ea_t ea = parse_address(addr_str);

    func_t* func = get_func(ea);
    if (!func) {
        return {{"error", "No function at address " + addr_str}};
    }

    json info;
    qstring fname;
    get_func_name(&fname, func->start_ea);
    info["name"] = fname.c_str();
    info["start"] = hex_addr(func->start_ea);
    info["end"] = hex_addr(func->end_ea);
    info["size"] = static_cast<int64_t>(func->size());

    // Flags
    json flags = json::array();
    if (func->flags & FUNC_NORET) flags.push_back("noreturn");
    if (func->flags & FUNC_LIB) flags.push_back("library");
    if (func->flags & FUNC_THUNK) flags.push_back("thunk");
    if (func->flags & FUNC_LUMINA) flags.push_back("lumina");
    info["flags"] = flags;

    // Frame info (IDA 9.x API)
    info["frame_size"] = static_cast<int64_t>(get_frame_size(func));
    info["local_var_size"] = static_cast<int64_t>(func->frsize);
    info["saved_reg_size"] = static_cast<int64_t>(func->frregs);
    info["arg_area_size"] = static_cast<int64_t>(func->argsize);

    return info;
}

json ToolExecutor::tool_get_disassembly(const json& input) {
    std::string addr_str = input.at("address").get<std::string>();
    ea_t ea = parse_address(addr_str);

    if (ea == BADADDR) {
        return {{"error", "Invalid address: " + addr_str}};
    }

    // If address is within a function, start from function start
    func_t* func = get_func(ea);
    if (func && ea == func->start_ea) {
        ea = func->start_ea;
    }

    int count = std::min(input.value("count", 30), config_.max_disasm_lines);

    json instructions = json::array();
    for (int i = 0; i < count; i++) {
        insn_t insn;
        int len = decode_insn(&insn, ea);
        if (len <= 0) break;

        json inst;
        inst["address"] = hex_addr(ea);

        // Bytes
        std::ostringstream bytes_ss;
        for (int b = 0; b < len; b++) {
            if (b > 0) bytes_ss << " ";
            bytes_ss << std::hex << std::setfill('0') << std::setw(2) << (int)get_byte(ea + b);
        }
        inst["bytes"] = bytes_ss.str();

        // Disassembly text
        qstring disasm;
        generate_disasm_line(&disasm, ea, GENDSM_FORCE_CODE);
        tag_remove(&disasm);
        inst["disasm"] = disasm.c_str();

        // Comment
        qstring cmt;
        if (get_cmt(&cmt, ea, false) > 0) {
            inst["comment"] = cmt.c_str();
        }

        instructions.push_back(inst);
        ea = next_head(ea, BADADDR);
        if (ea == BADADDR) break;
    }

    json result;
    result["instructions"] = instructions;
    if (func) {
        qstring fname;
        get_func_name(&fname, func->start_ea);
        result["function"] = fname.c_str();
    }
    return result;
}

json ToolExecutor::tool_decompile(const json& input) {
    // Try to init, but don't bail early — the cloud decompiler may work
    // even if init_hexrays_plugin() returned false
    ensure_decompiler();

    // Safety check: hexrays dispatch must be registered or we'd crash
    if (get_hexdsp() == nullptr) {
        return {{"error", "Hex-Rays decompiler is not available"}};
    }

    std::string addr_str = input.at("address").get<std::string>();
    ea_t ea = parse_address(addr_str);

    func_t* func = get_func(ea);
    if (!func) {
        return {{"error", "No function at address " + addr_str}};
    }

    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(func, &hf);
    if (!cfunc) {
        return {{"error", "Decompilation failed: " + std::string(hf.str.c_str())}};
    }

    // Mark decompiler as working (cloud decompiler confirmed available)
    has_decompiler_ = true;

    const strvec_t& sv = cfunc->get_pseudocode();

    // Build line_number -> address mapping using get_line_item
    std::map<int, ea_t> line_addrs;
    for (int i = 0; i < (int)sv.size(); i++) {
        qstring clean = sv[i].line;
        tag_remove(&clean);
        // Find first non-whitespace column
        int start_x = 0;
        while (start_x < (int)clean.length() && qisspace(clean[start_x]))
            start_x++;
        // Try to find a ctree item at this line
        ctree_item_t item;
        for (int x = start_x; x < (int)clean.length(); x++) {
            if (cfunc->get_line_item(sv[i].line.c_str(), x, false, nullptr, &item, nullptr)) {
                ea_t item_ea = item.get_ea();
                if (item_ea != BADADDR && item_ea >= func->start_ea && item_ea < func->end_ea) {
                    line_addrs[i] = item_ea;
                    break;
                }
            }
        }
    }

    // Build pseudocode with address annotations
    std::string pseudocode;
    json addr_map = json::object();
    for (int i = 0; i < (int)sv.size(); i++) {
        qstring line = sv[i].line;
        tag_remove(&line);
        auto it = line_addrs.find(i);
        if (it != line_addrs.end()) {
            std::string addr = hex_addr(it->second);
            pseudocode += "/* " + addr + " */  ";
            addr_map[std::to_string(i + 1)] = addr;  // 1-based line numbers
        }
        pseudocode += line.c_str();
        pseudocode += "\n";
    }

    // Extract local variables
    json vars = json::array();
    lvars_t& lvars = *cfunc->get_lvars();
    for (size_t i = 0; i < lvars.size(); i++) {
        json var;
        var["name"] = lvars[i].name.c_str();
        qstring type_str;
        if (lvars[i].type().print(&type_str)) {
            var["type"] = type_str.c_str();
        } else {
            var["type"] = "unknown";
        }
        vars.push_back(var);
    }

    json result;
    qstring fname;
    get_func_name(&fname, func->start_ea);
    result["function"] = fname.c_str();
    result["address"] = hex_addr(func->start_ea);
    result["pseudocode"] = pseudocode;
    result["line_addresses"] = addr_map;
    result["variables"] = vars;
    return result;
}

json ToolExecutor::tool_get_xrefs_to(const json& input) {
    std::string addr_str = input.at("address").get<std::string>();
    ea_t ea = parse_address(addr_str);
    int limit = input.value("limit", 50);

    if (ea == BADADDR) {
        return {{"error", "Invalid address: " + addr_str}};
    }

    json xrefs = json::array();
    xrefblk_t xb;
    int count = 0;
    for (bool ok = xb.first_to(ea, XREF_ALL); ok && count < limit; ok = xb.next_to()) {
        json xref;
        xref["from"] = hex_addr(xb.from);
        xref["type"] = xref_type_name(xb.type);

        func_t* func = get_func(xb.from);
        if (func) {
            qstring fname;
            get_func_name(&fname, func->start_ea);
            xref["from_function"] = fname.c_str();
        }

        xrefs.push_back(xref);
        count++;
    }

    json result;
    result["address"] = hex_addr(ea);
    result["name"] = get_name_at(ea);
    result["xrefs"] = xrefs;
    result["count"] = count;
    return result;
}

json ToolExecutor::tool_get_xrefs_from(const json& input) {
    std::string addr_str = input.at("address").get<std::string>();
    ea_t ea = parse_address(addr_str);
    int limit = input.value("limit", 50);

    if (ea == BADADDR) {
        return {{"error", "Invalid address: " + addr_str}};
    }

    json xrefs = json::array();
    xrefblk_t xb;
    int count = 0;
    for (bool ok = xb.first_from(ea, XREF_ALL); ok && count < limit; ok = xb.next_from()) {
        json xref;
        xref["to"] = hex_addr(xb.to);
        xref["type"] = xref_type_name(xb.type);

        std::string name = get_name_at(xb.to);
        if (!name.empty()) {
            xref["to_name"] = name;
        }

        xrefs.push_back(xref);
        count++;
    }

    json result;
    result["address"] = hex_addr(ea);
    result["xrefs"] = xrefs;
    result["count"] = count;
    return result;
}

json ToolExecutor::tool_get_strings(const json& input) {
    int offset = input.value("offset", 0);
    int limit = input.value("limit", 100);
    std::string filter = input.value("filter", "");
    int min_length = input.value("min_length", 4);

    std::string filter_lower = filter;
    std::transform(filter_lower.begin(), filter_lower.end(), filter_lower.begin(), ::tolower);

    // Build string list
    strwinsetup_t setup;
    setup.minlen = min_length;
    setup.strtypes.push_back(STRTYPE_C);
    setup.strtypes.push_back(STRTYPE_C_16);

    build_strlist();

    json strings = json::array();
    size_t total = get_strlist_qty();
    int count = 0;
    int skipped = 0;

    for (size_t i = 0; i < total && count < limit; i++) {
        string_info_t si;
        if (!get_strlist_item(&si, i)) continue;

        if (static_cast<int>(si.length) < min_length) continue;

        qstring str_content;
        get_strlit_contents(&str_content, si.ea, si.length, si.type);
        std::string content = str_content.c_str();

        // Apply filter
        if (!filter_lower.empty()) {
            std::string content_lower = content;
            std::transform(content_lower.begin(), content_lower.end(), content_lower.begin(), ::tolower);
            if (content_lower.find(filter_lower) == std::string::npos)
                continue;
        }

        if (skipped < offset) {
            skipped++;
            continue;
        }

        json s;
        s["address"] = hex_addr(si.ea);
        s["length"] = static_cast<int>(si.length);
        s["type"] = (si.type == STRTYPE_C) ? "ascii" : "unicode";
        s["string"] = content;
        strings.push_back(s);
        count++;
    }

    json result;
    result["strings"] = strings;
    result["total"] = static_cast<int>(total);
    result["count"] = count;
    return result;
}

json ToolExecutor::tool_list_segments(const json&) {
    json segments = json::array();
    int n = get_segm_qty();

    for (int i = 0; i < n; i++) {
        segment_t* seg = getnseg(i);
        if (!seg) continue;

        json s;
        qstring sname;
        get_segm_name(&sname, seg);
        s["name"] = sname.c_str();
        s["start"] = hex_addr(seg->start_ea);
        s["end"] = hex_addr(seg->end_ea);
        s["size"] = static_cast<int64_t>(seg->size());

        // Permissions (SEGPERM_EXEC=1, SEGPERM_WRITE=2, SEGPERM_READ=4)
        std::string perms;
        if (seg->perm & SEGPERM_READ) perms += "R";
        if (seg->perm & SEGPERM_WRITE) perms += "W";
        if (seg->perm & SEGPERM_EXEC) perms += "X";
        s["permissions"] = perms;

        // Segment type
        switch (seg->type) {
            case SEG_CODE: s["type"] = "CODE"; break;
            case SEG_DATA: s["type"] = "DATA"; break;
            case SEG_BSS:  s["type"] = "BSS"; break;
            case SEG_XTRN: s["type"] = "EXTERN"; break;
            default:       s["type"] = "OTHER"; break;
        }

        segments.push_back(s);
    }

    json result;
    result["segments"] = segments;
    result["count"] = n;
    return result;
}

json ToolExecutor::tool_get_bytes(const json& input) {
    std::string addr_str = input.at("address").get<std::string>();
    ea_t ea = parse_address(addr_str);
    int size = std::min(input.value("size", 64), config_.max_bytes_read);

    if (ea == BADADDR) {
        return {{"error", "Invalid address: " + addr_str}};
    }

    std::ostringstream hex_ss;
    for (int i = 0; i < size; i++) {
        if (i > 0) hex_ss << " ";
        hex_ss << std::hex << std::setfill('0') << std::setw(2) << (int)get_byte(ea + i);
    }

    json result;
    result["address"] = hex_addr(ea);
    result["size"] = size;
    result["hex"] = hex_ss.str();
    return result;
}

json ToolExecutor::tool_search_bytes(const json& input) {
    std::string pattern_str = input.at("pattern").get<std::string>();
    int limit = input.value("limit", 10);

    ea_t start_ea = BADADDR;
    if (input.contains("start_address")) {
        start_ea = parse_address(input["start_address"].get<std::string>());
    }
    if (start_ea == BADADDR) {
        segment_t* seg = getnseg(0);
        if (seg) start_ea = seg->start_ea;
    }

    if (start_ea == BADADDR) {
        return {{"error", "No valid start address and no segments found"}};
    }

    // Parse pattern: convert "48 8B ? ? 90" to compiled binary pattern
    compiled_binpat_vec_t binpat;
    qstring errbuf;
    if (!parse_binpat_str(&binpat, start_ea, pattern_str.c_str(), 16, PBSENC_DEF1BPU, &errbuf)) {
        return {{"error", "Invalid pattern: " + std::string(errbuf.c_str())}};
    }

    json matches = json::array();
    ea_t cur_ea = start_ea;

    for (int i = 0; i < limit; i++) {
        ea_t found = bin_search(cur_ea, BADADDR, binpat, BIN_SEARCH_FORWARD);
        if (found == BADADDR) break;

        json m;
        m["address"] = hex_addr(found);
        std::string name = get_name_at(found);
        if (!name.empty()) m["name"] = name;

        func_t* func = get_func(found);
        if (func) {
            qstring fname;
            get_func_name(&fname, func->start_ea);
            m["function"] = fname.c_str();
        }

        matches.push_back(m);
        cur_ea = found + 1;
    }

    json result;
    result["pattern"] = pattern_str;
    result["matches"] = matches;
    result["count"] = static_cast<int>(matches.size());
    return result;
}

json ToolExecutor::tool_get_names(const json& input) {
    int offset = input.value("offset", 0);
    int limit = input.value("limit", 100);
    std::string filter = input.value("filter", "");

    std::string filter_lower = filter;
    std::transform(filter_lower.begin(), filter_lower.end(), filter_lower.begin(), ::tolower);

    json names = json::array();
    int count = 0;
    int skipped = 0;

    for (size_t i = 0; i < get_nlist_size() && count < limit; i++) {
        ea_t ea = get_nlist_ea(i);
        const char* name_cstr = get_nlist_name(i);
        std::string name_str = name_cstr ? name_cstr : "";

        // Apply filter
        if (!filter_lower.empty()) {
            std::string name_lower = name_str;
            std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
            if (name_lower.find(filter_lower) == std::string::npos)
                continue;
        }

        if (skipped < offset) {
            skipped++;
            continue;
        }

        json n;
        n["address"] = hex_addr(ea);
        n["name"] = name_str;

        // Determine type
        func_t* func = get_func(ea);
        if (func && func->start_ea == ea) {
            n["type"] = "function";
        } else {
            flags64_t fl = get_flags(ea);
            if (is_data(fl)) n["type"] = "data";
            else n["type"] = "label";
        }

        names.push_back(n);
        count++;
    }

    json result;
    result["names"] = names;
    result["total"] = static_cast<int>(get_nlist_size());
    result["count"] = count;
    return result;
}

json ToolExecutor::tool_rename_address(const json& input) {
    std::string addr_str = input.at("address").get<std::string>();
    std::string new_name = input.at("new_name").get<std::string>();
    ea_t ea = parse_address(addr_str);

    if (ea == BADADDR) {
        return {{"error", "Invalid address: " + addr_str}};
    }

    std::string old_name = get_name_at(ea);
    bool ok = set_name(ea, new_name.c_str(), SN_CHECK | SN_NOWARN);

    if (!ok) {
        return {{"error", "Failed to rename address " + addr_str + " to '" + new_name + "'"}};
    }

    json result;
    result["address"] = hex_addr(ea);
    result["old_name"] = old_name;
    result["new_name"] = new_name;
    result["success"] = true;
    return result;
}

json ToolExecutor::tool_set_comment(const json& input) {
    std::string addr_str = input.at("address").get<std::string>();
    std::string comment = input.at("comment").get<std::string>();
    bool repeatable = input.value("repeatable", false);
    ea_t ea = parse_address(addr_str);

    if (ea == BADADDR) {
        return {{"error", "Invalid address: " + addr_str}};
    }

    bool ok = set_cmt(ea, comment.c_str(), repeatable);

    json result;
    result["address"] = hex_addr(ea);
    result["comment"] = comment;
    result["repeatable"] = repeatable;
    result["success"] = ok;
    return result;
}

json ToolExecutor::tool_get_current_address(const json&) {
    ea_t ea = get_screen_ea();

    json result;
    result["address"] = hex_addr(ea);

    std::string name = get_name_at(ea);
    if (!name.empty()) {
        result["name"] = name;
    }

    func_t* func = get_func(ea);
    if (func) {
        qstring fname;
        get_func_name(&fname, func->start_ea);
        result["function"] = fname.c_str();
        result["function_address"] = hex_addr(func->start_ea);
    }

    return result;
}

json ToolExecutor::tool_jump_to_address(const json& input) {
    std::string addr_str = input.at("address").get<std::string>();
    ea_t ea = parse_address(addr_str);

    if (ea == BADADDR) {
        return {{"error", "Invalid address: " + addr_str}};
    }

    bool ok = jumpto(ea);

    json result;
    result["address"] = hex_addr(ea);
    result["success"] = ok;
    return result;
}

json ToolExecutor::tool_rename_local_variable(const json& input) {
    ensure_decompiler();
    if (get_hexdsp() == nullptr) {
        return {{"error", "Hex-Rays decompiler is not available"}};
    }

    std::string addr_str = input.at("address").get<std::string>();
    std::string old_name = input.at("old_name").get<std::string>();
    std::string new_name = input.at("new_name").get<std::string>();
    ea_t ea = parse_address(addr_str);

    func_t* func = get_func(ea);
    if (!func) {
        return {{"error", "No function at address " + addr_str}};
    }

    // Decompile to get cfunc and access lvars
    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(func, &hf);
    if (!cfunc) {
        return {{"error", "Decompilation failed: " + std::string(hf.str.c_str())}};
    }

    // Find the lvar by name
    lvars_t& lvars = *cfunc->get_lvars();
    lvar_t* target = nullptr;
    for (size_t i = 0; i < lvars.size(); i++) {
        if (lvars[i].name == old_name.c_str()) {
            target = &lvars[i];
            break;
        }
    }

    if (!target) {
        // List available variable names in the error to help the agent
        std::string available;
        for (size_t i = 0; i < lvars.size(); i++) {
            if (i > 0) available += ", ";
            available += lvars[i].name.c_str();
        }
        return {{"error", "Variable '" + old_name + "' not found. Available variables: " + available}};
    }

    // Use the Hex-Rays API to rename the lvar persistently
    lvar_saved_info_t info;
    info.ll = static_cast<const lvar_locator_t&>(*target);
    info.size = target->width;
    info.type = target->type();
    info.name = new_name.c_str();

    bool ok = modify_user_lvar_info(func->start_ea, MLI_NAME, info);
    if (!ok) {
        return {{"error", "Failed to rename variable '" + old_name + "' to '" + new_name + "'"}};
    }

    // Invalidate cached decompilation so pseudocode windows refresh
    mark_cfunc_dirty(func->start_ea);

    json result;
    result["function"] = hex_addr(func->start_ea);
    result["old_name"] = old_name;
    result["new_name"] = new_name;
    result["success"] = true;
    return result;
}

json ToolExecutor::tool_set_decompiler_comment(const json& input) {
    ensure_decompiler();
    if (get_hexdsp() == nullptr) {
        return {{"error", "Hex-Rays decompiler is not available"}};
    }

    std::string func_addr_str = input.at("function_address").get<std::string>();
    std::string addr_str = input.at("address").get<std::string>();
    std::string comment = input.at("comment").get<std::string>();

    ea_t func_ea = parse_address(func_addr_str);
    ea_t ea = parse_address(addr_str);

    func_t* func = get_func(func_ea);
    if (!func) {
        return {{"error", "No function at address " + func_addr_str}};
    }

    if (ea == BADADDR) {
        return {{"error", "Invalid comment address: " + addr_str}};
    }

    // Decompile to get cfunc
    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(func, &hf);
    if (!cfunc) {
        return {{"error", "Decompilation failed: " + std::string(hf.str.c_str())}};
    }

    // Set the pseudocode line comment using treeloc_t
    treeloc_t loc;
    loc.ea = ea;
    loc.itp = ITP_SEMI;  // comment at end of statement (semicolon position)
    cfunc->set_user_cmt(loc, comment.c_str());
    cfunc->save_user_cmts();

    // Invalidate cached decompilation so pseudocode windows refresh
    mark_cfunc_dirty(func->start_ea);

    json result;
    result["function"] = hex_addr(func->start_ea);
    result["address"] = hex_addr(ea);
    result["comment"] = comment;
    result["success"] = true;
    return result;
}

json ToolExecutor::tool_set_local_variable_type(const json& input) {
    ensure_decompiler();
    if (get_hexdsp() == nullptr) {
        return {{"error", "Hex-Rays decompiler is not available"}};
    }

    std::string addr_str = input.at("address").get<std::string>();
    std::string var_name = input.at("variable_name").get<std::string>();
    std::string type_str = input.at("new_type").get<std::string>();
    ea_t ea = parse_address(addr_str);

    func_t* func = get_func(ea);
    if (!func) {
        return {{"error", "No function at address " + addr_str}};
    }

    // Decompile to get cfunc and access lvars
    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(func, &hf);
    if (!cfunc) {
        return {{"error", "Decompilation failed: " + std::string(hf.str.c_str())}};
    }

    // Find the lvar by name
    lvars_t& lvars = *cfunc->get_lvars();
    lvar_t* target = nullptr;
    for (size_t i = 0; i < lvars.size(); i++) {
        if (lvars[i].name == var_name.c_str()) {
            target = &lvars[i];
            break;
        }
    }

    if (!target) {
        std::string available;
        for (size_t i = 0; i < lvars.size(); i++) {
            if (i > 0) available += ", ";
            available += lvars[i].name.c_str();
        }
        return {{"error", "Variable '" + var_name + "' not found. Available variables: " + available}};
    }

    // Parse the type string into a tinfo_t
    // parse_decl expects a full declaration like "int *x;" - we append a dummy name
    tinfo_t new_type;
    if (!parse_decl(&new_type, nullptr, nullptr, (type_str + " __x;").c_str(), PT_SIL)) {
        return {{"error", "Failed to parse type '" + type_str + "'. Use valid C type syntax."}};
    }

    // Apply the type via modify_user_lvar_info
    lvar_saved_info_t info;
    info.ll = static_cast<const lvar_locator_t&>(*target);
    info.size = target->width;
    info.type = new_type;
    info.name = target->name;

    bool ok = modify_user_lvar_info(func->start_ea, MLI_TYPE, info);
    if (!ok) {
        return {{"error", "Failed to set type of variable '" + var_name + "' to '" + type_str + "'"}};
    }

    // Invalidate cached decompilation so pseudocode windows refresh
    mark_cfunc_dirty(func->start_ea);

    json result;
    result["function"] = hex_addr(func->start_ea);
    result["variable"] = var_name;
    result["new_type"] = type_str;
    result["success"] = true;
    return result;
}

// --- Import callback context for enum_import_names ---
struct import_enum_ctx {
    json* imports;
    int* count;
    int* skipped;
    int* total;
    int offset;
    int limit;
    std::string module;
};

static int idaapi import_enum_cb(ea_t ea, const char* name, uval_t ord, void* ud) {
    auto* ctx = static_cast<import_enum_ctx*>(ud);
    (*ctx->total)++;

    if (*ctx->skipped < ctx->offset) {
        (*ctx->skipped)++;
        return 1;
    }
    if (*ctx->count >= ctx->limit) return 0;

    json imp;
    imp["module"] = ctx->module;
    imp["name"] = name ? name : "";
    imp["address"] = hex_addr(ea);
    if (ord != 0 && ord != static_cast<uval_t>(-1)) {
        imp["ordinal"] = static_cast<int64_t>(ord);
    }

    ctx->imports->push_back(imp);
    (*ctx->count)++;
    return 1;
}

json ToolExecutor::tool_list_imports(const json& input) {
    int offset = input.value("offset", 0);
    int limit = std::min(input.value("limit", 100), 500);
    std::string module_filter = input.value("module", "");

    std::string filter_lower = module_filter;
    std::transform(filter_lower.begin(), filter_lower.end(), filter_lower.begin(), ::tolower);

    json imports = json::array();
    int count = 0;
    int skipped = 0;
    int total = 0;

    int n_modules = get_import_module_qty();

    for (int mod_idx = 0; mod_idx < n_modules && count < limit; mod_idx++) {
        qstring mod_name;
        get_import_module_name(&mod_name, mod_idx);
        std::string mod_str = mod_name.c_str();

        if (!filter_lower.empty()) {
            std::string mod_lower = mod_str;
            std::transform(mod_lower.begin(), mod_lower.end(), mod_lower.begin(), ::tolower);
            if (mod_lower.find(filter_lower) == std::string::npos)
                continue;
        }

        import_enum_ctx ctx = { &imports, &count, &skipped, &total, offset, limit, mod_str };
        enum_import_names(mod_idx, import_enum_cb, &ctx);
    }

    json result;
    result["imports"] = imports;
    result["count"] = count;
    result["total"] = total;
    result["offset"] = offset;
    return result;
}

json ToolExecutor::tool_get_callees(const json& input) {
    std::string addr_str = input.at("address").get<std::string>();
    ea_t ea = parse_address(addr_str);
    int limit = input.value("limit", 50);

    func_t* func = get_func(ea);
    if (!func) {
        return {{"error", "No function at address " + addr_str}};
    }

    json callees = json::array();
    std::set<ea_t> seen;
    int count = 0;

    ea_t cur_ea = func->start_ea;
    while (cur_ea < func->end_ea && count < limit) {
        xrefblk_t xb;
        for (bool ok = xb.first_from(cur_ea, XREF_ALL); ok; ok = xb.next_from()) {
            if (xb.type == fl_CF || xb.type == fl_CN) {
                func_t* callee = get_func(xb.to);
                if (callee && seen.find(callee->start_ea) == seen.end()) {
                    seen.insert(callee->start_ea);

                    json c;
                    c["address"] = hex_addr(callee->start_ea);
                    qstring fname;
                    get_func_name(&fname, callee->start_ea);
                    c["name"] = fname.c_str();
                    c["type"] = xref_type_name(xb.type);
                    c["call_site"] = hex_addr(cur_ea);
                    callees.push_back(c);
                    count++;
                    if (count >= limit) break;
                }
            }
        }
        cur_ea = next_head(cur_ea, func->end_ea);
        if (cur_ea == BADADDR) break;
    }

    json result;
    qstring fname;
    get_func_name(&fname, func->start_ea);
    result["function"] = fname.c_str();
    result["address"] = hex_addr(func->start_ea);
    result["callees"] = callees;
    result["count"] = count;
    return result;
}

json ToolExecutor::tool_get_basic_blocks(const json& input) {
    std::string addr_str = input.at("address").get<std::string>();
    ea_t ea = parse_address(addr_str);

    func_t* func = get_func(ea);
    if (!func) {
        return {{"error", "No function at address " + addr_str}};
    }

    qflow_chart_t flow("", func, func->start_ea, func->end_ea, 0);

    json blocks = json::array();
    for (int i = 0; i < flow.size(); i++) {
        const qbasic_block_t& bb = flow.blocks[i];

        json block;
        block["id"] = i;
        block["start"] = hex_addr(bb.start_ea);
        block["end"] = hex_addr(bb.end_ea);
        block["size"] = static_cast<int64_t>(bb.end_ea - bb.start_ea);

        json succs = json::array();
        for (int j = 0; j < flow.nsucc(i); j++) {
            succs.push_back(flow.succ(i, j));
        }
        block["successors"] = succs;

        json preds = json::array();
        for (int j = 0; j < flow.npred(i); j++) {
            preds.push_back(flow.pred(i, j));
        }
        block["predecessors"] = preds;

        if (flow.nsucc(i) == 0) block["type"] = "exit";
        else if (flow.nsucc(i) > 1) block["type"] = "conditional";
        else block["type"] = "sequential";

        blocks.push_back(block);
    }

    json result;
    qstring fname;
    get_func_name(&fname, func->start_ea);
    result["function"] = fname.c_str();
    result["address"] = hex_addr(func->start_ea);
    result["blocks"] = blocks;
    result["count"] = flow.size();
    return result;
}

json ToolExecutor::tool_get_callgraph(const json& input) {
    std::string addr_str = input.at("address").get<std::string>();
    ea_t root_ea = parse_address(addr_str);
    int max_depth = std::min(input.value("depth", 3), 10);
    int max_nodes = std::min(input.value("max_nodes", 100), 500);

    func_t* root_func = get_func(root_ea);
    if (!root_func) {
        return {{"error", "No function at address " + addr_str}};
    }

    std::set<ea_t> visited;
    std::map<ea_t, std::string> node_names;
    json edges = json::array();

    // BFS queue: (function_ea, depth)
    std::queue<std::pair<ea_t, int>> queue;
    queue.push({root_func->start_ea, 0});
    visited.insert(root_func->start_ea);

    {
        qstring fname;
        get_func_name(&fname, root_func->start_ea);
        node_names[root_func->start_ea] = fname.c_str();
    }

    while (!queue.empty() && static_cast<int>(visited.size()) < max_nodes) {
        auto [func_ea, depth] = queue.front();
        queue.pop();

        if (depth >= max_depth) continue;

        func_t* func = get_func(func_ea);
        if (!func) continue;

        ea_t cur_ea = func->start_ea;
        while (cur_ea < func->end_ea) {
            xrefblk_t xb;
            for (bool ok = xb.first_from(cur_ea, XREF_ALL); ok; ok = xb.next_from()) {
                if (xb.type == fl_CF || xb.type == fl_CN) {
                    func_t* callee = get_func(xb.to);
                    if (callee) {
                        ea_t callee_ea = callee->start_ea;

                        json edge;
                        edge["from"] = hex_addr(func_ea);
                        edge["to"] = hex_addr(callee_ea);
                        edges.push_back(edge);

                        if (visited.find(callee_ea) == visited.end()
                            && static_cast<int>(visited.size()) < max_nodes) {
                            visited.insert(callee_ea);
                            qstring cname;
                            get_func_name(&cname, callee_ea);
                            node_names[callee_ea] = cname.c_str();
                            queue.push({callee_ea, depth + 1});
                        }
                    }
                }
            }
            cur_ea = next_head(cur_ea, func->end_ea);
            if (cur_ea == BADADDR) break;
        }
    }

    json nodes = json::array();
    for (const auto& [ea, name] : node_names) {
        json node;
        node["address"] = hex_addr(ea);
        node["name"] = name;
        node["is_root"] = (ea == root_func->start_ea);
        nodes.push_back(node);
    }

    json result;
    result["root"] = hex_addr(root_func->start_ea);
    result["root_name"] = node_names[root_func->start_ea];
    result["nodes"] = nodes;
    result["edges"] = edges;
    result["node_count"] = static_cast<int>(nodes.size());
    result["edge_count"] = static_cast<int>(edges.size());
    result["max_depth"] = max_depth;
    return result;
}

json ToolExecutor::tool_set_function_type(const json& input) {
    std::string addr_str = input.at("address").get<std::string>();
    std::string prototype = input.at("prototype").get<std::string>();
    ea_t ea = parse_address(addr_str);

    func_t* func = get_func(ea);
    if (!func) {
        return {{"error", "No function at address " + addr_str}};
    }

    tinfo_t new_type;
    if (!parse_decl(&new_type, nullptr, nullptr, (prototype + ";").c_str(), PT_SIL)) {
        return {{"error", "Failed to parse prototype: '" + prototype + "'. Use valid C syntax."}};
    }

    if (!new_type.is_func()) {
        return {{"error", "Parsed type is not a function type. Provide a function signature."}};
    }

    if (!apply_tinfo(func->start_ea, new_type, TINFO_DEFINITE)) {
        return {{"error", "Failed to apply function type to " + addr_str}};
    }

    // Invalidate cached decompilation so pseudocode windows refresh
    mark_cfunc_dirty(func->start_ea);

    json result;
    result["address"] = hex_addr(func->start_ea);
    qstring fname;
    get_func_name(&fname, func->start_ea);
    result["function"] = fname.c_str();
    result["prototype"] = prototype;
    result["success"] = true;
    return result;
}

json ToolExecutor::tool_declare_type(const json& input) {
    std::string decl = input.at("declaration").get<std::string>();

    tinfo_t new_type;
    qstring parsed_name;
    if (!parse_decl(&new_type, &parsed_name, nullptr, (decl).c_str(), PT_TYP)) {
        return {{"error", "Failed to parse type declaration: '" + decl + "'. Use valid C type syntax."}};
    }

    const char* final_name = parsed_name.c_str();
    if (!final_name || !final_name[0]) {
        return {{"error", "Could not determine type name from declaration. Use a named type (struct/union/typedef/enum)."}};
    }

    til_t* ti = get_idati();
    if (!ti) {
        return {{"error", "Failed to get IDA type library"}};
    }

    uint32 ordinal = alloc_type_ordinal(ti);
    if (new_type.set_numbered_type(ti, ordinal, NTF_REPLACE, final_name) != TERR_OK) {
        return {{"error", "Failed to add type '" + std::string(final_name) + "' to type library"}};
    }

    json result;
    result["name"] = final_name;
    result["declaration"] = decl;
    result["success"] = true;
    return result;
}

json ToolExecutor::tool_define_function(const json& input) {
    std::string addr_str = input.at("address").get<std::string>();
    ea_t start_ea = parse_address(addr_str);

    if (start_ea == BADADDR) {
        return {{"error", "Invalid start address: " + addr_str}};
    }

    func_t* existing = get_func(start_ea);
    if (existing && existing->start_ea == start_ea) {
        qstring fname;
        get_func_name(&fname, start_ea);
        return {{"error", "Function already exists at " + addr_str + ": " + std::string(fname.c_str())}};
    }

    ea_t end_ea = BADADDR;
    if (input.contains("end_address")) {
        std::string end_str = input["end_address"].get<std::string>();
        end_ea = parse_address(end_str);
        if (end_ea == BADADDR) {
            return {{"error", "Invalid end address: " + end_str}};
        }
    }

    if (!add_func(start_ea, end_ea)) {
        return {{"error", "Failed to create function at " + addr_str}};
    }

    func_t* new_func = get_func(start_ea);
    if (!new_func) {
        return {{"error", "Function creation reported success but function not found"}};
    }

    json result;
    result["address"] = hex_addr(new_func->start_ea);
    result["end"] = hex_addr(new_func->end_ea);
    result["size"] = static_cast<int64_t>(new_func->size());
    qstring fname;
    get_func_name(&fname, new_func->start_ea);
    result["name"] = fname.c_str();
    result["success"] = true;
    return result;
}

json ToolExecutor::tool_get_stack_frame(const json& input) {
    std::string addr_str = input.at("address").get<std::string>();
    ea_t ea = parse_address(addr_str);

    func_t* func = get_func(ea);
    if (!func) {
        return {{"error", "No function at address " + addr_str}};
    }

    // IDA 9.x: frame is accessed via tinfo_t + get_udt_details
    tinfo_t frame_type;
    if (!get_func_frame(&frame_type, func)) {
        return {{"error", "Function has no stack frame information"}};
    }

    udt_type_data_t udt;
    if (!frame_type.get_udt_details(&udt)) {
        return {{"error", "Failed to get frame details"}};
    }

    json members = json::array();
    for (size_t i = 0; i < udt.size(); i++) {
        const udm_t& udm = udt[i];

        json m;
        m["offset"] = static_cast<int64_t>(udm.offset / 8);  // bits to bytes
        m["name"] = udm.name.c_str();
        m["size"] = static_cast<int64_t>(udm.size / 8);  // bits to bytes

        if (!udm.type.empty()) {
            qstring type_str;
            udm.type.print(&type_str);
            m["type"] = type_str.c_str();
        } else {
            m["type"] = "unknown";
        }

        members.push_back(m);
    }

    json result;
    qstring fname;
    get_func_name(&fname, func->start_ea);
    result["function"] = fname.c_str();
    result["address"] = hex_addr(func->start_ea);
    result["frame_size"] = static_cast<int64_t>(get_frame_size(func));
    result["members"] = members;
    result["member_count"] = static_cast<int>(members.size());
    return result;
}

} // namespace ida_chat
