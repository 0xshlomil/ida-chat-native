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

void ToolExecutor::execute_tool(const QString& tool_name, const QString& input, QString* result) {
    json input_json;
    try {
        input_json = json::parse(input.toStdString());
    } catch (...) {
        input_json = json::object();
    }

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
        else {
            output = {{"error", "Unknown tool: " + name}};
        }
    } catch (const std::exception& e) {
        output = {{"error", std::string("Tool execution error: ") + e.what()}};
    }

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
    info["has_decompiler"] = has_decompiler_;

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
    if (!has_decompiler_) {
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

    const strvec_t& sv = cfunc->get_pseudocode();
    std::string pseudocode;
    for (size_t i = 0; i < sv.size(); i++) {
        qstring line = sv[i].line;
        tag_remove(&line);
        pseudocode += line.c_str();
        pseudocode += "\n";
    }

    json result;
    qstring fname;
    get_func_name(&fname, func->start_ea);
    result["function"] = fname.c_str();
    result["address"] = hex_addr(func->start_ea);
    result["pseudocode"] = pseudocode;
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
    if (!has_decompiler_) {
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

    json result;
    result["function"] = hex_addr(func->start_ea);
    result["old_name"] = old_name;
    result["new_name"] = new_name;
    result["success"] = true;
    return result;
}

json ToolExecutor::tool_set_decompiler_comment(const json& input) {
    if (!has_decompiler_) {
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

    json result;
    result["function"] = hex_addr(func->start_ea);
    result["address"] = hex_addr(ea);
    result["comment"] = comment;
    result["success"] = true;
    return result;
}

json ToolExecutor::tool_set_local_variable_type(const json& input) {
    if (!has_decompiler_) {
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

    json result;
    result["function"] = hex_addr(func->start_ea);
    result["variable"] = var_name;
    result["new_type"] = type_str;
    result["success"] = true;
    return result;
}

} // namespace ida_chat
