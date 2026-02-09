#include "plugin.h"
#include "chat_widget.h"

#include <kernwin.hpp>
#include <QVBoxLayout>

namespace ida_chat {

static const char* WIDGET_TITLE = "IDA Chat";
static const char* ACTION_NAME = "ida-chat:toggle";
static const char* ACTION_LABEL = "Toggle IDA Chat";
static const char* ACTION_SHORTCUT = "Ctrl+Shift+C";

// -------------------------------------------------------------------------
// Action handler for toggling the chat widget
// -------------------------------------------------------------------------
struct toggle_action_t : public action_handler_t {
    IdaChatPlugin* plugin;

    toggle_action_t(IdaChatPlugin* p) : plugin(p) {}

    int idaapi activate(action_activation_ctx_t*) override {
        plugin->run(0);
        return 1;
    }

    action_state_t idaapi update(action_update_ctx_t*) override {
        return AST_ENABLE_ALWAYS;
    }
};

static toggle_action_t* toggle_handler = nullptr;

// -------------------------------------------------------------------------
// Plugin implementation
// -------------------------------------------------------------------------
IdaChatPlugin::IdaChatPlugin() {
    msg("IDA Chat: Plugin loaded\n");

    // Register the toggle action
    toggle_handler = new toggle_action_t(this);

    action_desc_t desc = ACTION_DESC_LITERAL(
        ACTION_NAME,
        ACTION_LABEL,
        toggle_handler,
        ACTION_SHORTCUT,
        "Toggle the IDA Chat panel",
        -1  // no icon
    );

    if (!register_action(desc)) {
        msg("IDA Chat: Failed to register action\n");
    }

    // Attach to View menu
    attach_action_to_menu("View/", ACTION_NAME, SETMENU_APP);
}

IdaChatPlugin::~IdaChatPlugin() {
    // Close the widget if open
    if (widget_) {
        TWidget* tw = find_widget(WIDGET_TITLE);
        if (tw) {
            close_widget(tw, 0);
        }
        widget_ = nullptr;
    }

    detach_action_from_menu("View/", ACTION_NAME);
    unregister_action(ACTION_NAME);
    delete toggle_handler;
    toggle_handler = nullptr;

    msg("IDA Chat: Plugin unloaded\n");
}

bool idaapi IdaChatPlugin::run(size_t) {
    toggle_widget();
    return true;
}

void IdaChatPlugin::toggle_widget() {
    TWidget* tw = find_widget(WIDGET_TITLE);

    if (tw) {
        // Widget exists - close it (toggle off)
        close_widget(tw, 0);
        widget_ = nullptr;
    } else {
        // Create an IDA dockable widget.
        // In IDA 9.x, TWidget is typedef for QT::QWidget, so create_empty_widget
        // returns something we can parent our ChatWidget into directly.
        tw = create_empty_widget(WIDGET_TITLE);
        display_widget(tw, WOPN_DP_RIGHT | WOPN_RESTORE);

        // TWidget* is QWidget* (in QT namespace). Parent our widget into it.
        auto* container = reinterpret_cast<QWidget*>(tw);
        auto* layout = new QVBoxLayout(container);
        layout->setContentsMargins(0, 0, 0, 0);

        widget_ = new ChatWidget(container);
        layout->addWidget(widget_);
    }
}

} // namespace ida_chat

// -------------------------------------------------------------------------
// IDA plugin exports
// -------------------------------------------------------------------------
static plugmod_t* idaapi init() {
    return new ida_chat::IdaChatPlugin();
}

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,       // Load for every database
    init,               // init
    nullptr,            // term (handled by plugmod_t destructor)
    nullptr,            // run (handled by plugmod_t::run)
    "AI-powered binary analysis chat using Claude",  // comment
    "",                 // help
    "IDA Chat",         // wanted name
    "Ctrl+Shift+C"     // wanted hotkey
};
