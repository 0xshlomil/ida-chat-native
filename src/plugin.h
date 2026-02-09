#pragma once

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

namespace ida_chat {

class ChatWidget;

// IDA 9.x plugmod_t-based plugin
class IdaChatPlugin : public plugmod_t {
public:
    IdaChatPlugin();
    ~IdaChatPlugin() override;

    bool idaapi run(size_t arg) override;

private:
    void toggle_widget();
    ChatWidget* widget_ = nullptr;
};

} // namespace ida_chat
