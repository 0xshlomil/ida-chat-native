#include "config.h"

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <unordered_map>
#include <vector>

#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QComboBox>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QSpinBox>

namespace ida_chat {

// ---------------------------------------------------------------------------
// Theme presets
// ---------------------------------------------------------------------------

Theme get_theme(bool dark_mode) {
    if (dark_mode) {
        // Catppuccin Mocha
        return {
            "#1e1e2e",  // base
            "#181825",  // mantle
            "#313244",  // surface0
            "#45475a",  // surface1
            "#585b70",  // surface2
            "#6c7086",  // overlay0
            "#cdd6f4",  // text
            "#a6adc8",  // subtext
            "#89b4fa",  // blue
            "#74c7ec",  // sapphire
            "#a6e3a1",  // green
            "#f38ba8",  // red
            "#fab387",  // peach
            "#eba0ac",  // pink
        };
    }
    // Catppuccin Latte
    return {
        "#eff1f5",  // base
        "#e6e9ef",  // mantle
        "#ccd0da",  // surface0
        "#bcc0cc",  // surface1
        "#acb0be",  // surface2
        "#9ca0b0",  // overlay0
        "#4c4f69",  // text
        "#6c6f85",  // subtext
        "#1e66f5",  // blue
        "#209fb5",  // sapphire
        "#40a02b",  // green
        "#d20f39",  // red
        "#fe640b",  // peach
        "#ea76cb",  // pink
    };
}

std::string get_dialog_style(const Theme& t) {
    std::ostringstream ss;
    ss << "QDialog { background-color: " << t.base << "; color: " << t.text << "; }"
       << "QLabel { color: " << t.text << "; }"
       << "QComboBox {"
       << "  background-color: " << t.surface0 << "; color: " << t.text << "; border: 1px solid " << t.surface1 << ";"
       << "  border-radius: 4px; padding: 4px 8px; min-width: 240px;"
       << "}"
       << "QComboBox::drop-down { border: none; }"
       << "QComboBox QAbstractItemView {"
       << "  background-color: " << t.surface0 << "; color: " << t.text << ";"
       << "  selection-background-color: " << t.surface1 << ";"
       << "}"
       << "QLineEdit {"
       << "  background-color: " << t.surface0 << "; color: " << t.text << "; border: 1px solid " << t.surface1 << ";"
       << "  border-radius: 4px; padding: 4px 8px; min-width: 300px;"
       << "}"
       << "QSpinBox {"
       << "  background-color: " << t.surface0 << "; color: " << t.text << "; border: 1px solid " << t.surface1 << ";"
       << "  border-radius: 4px; padding: 4px 8px;"
       << "}"
       << "QPushButton {"
       << "  background-color: " << t.surface1 << "; color: " << t.text << "; border: none;"
       << "  border-radius: 4px; padding: 6px 16px;"
       << "}"
       << "QPushButton:hover { background-color: " << t.surface2 << "; }"
       << "QPushButton:default {"
       << "  background-color: " << t.blue << "; color: " << t.base << "; font-weight: bold;"
       << "}"
       << "QPushButton:default:hover { background-color: " << t.sapphire << "; }";
    return ss.str();
}

// ---------------------------------------------------------------------------
// Config file I/O
// ---------------------------------------------------------------------------

static std::string config_file_path() {
    const char* home = std::getenv("HOME");
    if (!home) home = "/tmp";
    return std::string(home) + "/.idapro/ida-chat.conf";
}

// Parse all key=value pairs from config file into a map
static std::unordered_map<std::string, std::string> read_config_file(const std::string& path) {
    std::unordered_map<std::string, std::string> kv;
    std::ifstream f(path);
    if (!f.is_open()) return kv;

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        while (!key.empty() && key.back() == ' ') key.pop_back();
        while (!val.empty() && val.front() == ' ') val.erase(val.begin());
        kv[key] = val;
    }
    return kv;
}

static std::string str_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

Config load_config() {
    Config cfg;

    // Read config file first (env vars override below)
    auto kv = read_config_file(config_file_path());

    // Backend: env var IDA_CHAT_BACKEND or config file "backend"
    const char* env_backend = std::getenv("IDA_CHAT_BACKEND");
    std::string backend_str;
    if (env_backend && env_backend[0] != '\0') {
        backend_str = str_lower(env_backend);
    } else if (kv.count("backend")) {
        backend_str = str_lower(kv["backend"]);
    }
    if (backend_str == "openai") {
        cfg.backend = Backend::OPENAI;
    }

    // API URL: env var IDA_CHAT_API_URL or config file "api_url"
    const char* env_url = std::getenv("IDA_CHAT_API_URL");
    if (env_url && env_url[0] != '\0') {
        cfg.api_url = env_url;
    } else if (kv.count("api_url")) {
        cfg.api_url = kv["api_url"];
    }

    // API key: env vars take priority, then config file
    const char* env_key = nullptr;
    if (cfg.backend == Backend::OPENAI) {
        env_key = std::getenv("OPENAI_API_KEY");
    }
    if (!env_key || env_key[0] == '\0') {
        env_key = std::getenv("ANTHROPIC_API_KEY");
    }
    if (env_key && env_key[0] != '\0') {
        cfg.api_key = env_key;
    } else if (kv.count("api_key")) {
        cfg.api_key = kv["api_key"];
    }

    // Model override
    if (kv.count("model")) cfg.model = kv["model"];

    // Other settings
    if (kv.count("max_turns")) cfg.max_turns = std::stoi(kv["max_turns"]);
    if (kv.count("max_tokens")) cfg.max_tokens = std::stoi(kv["max_tokens"]);
    if (kv.count("max_disasm_lines")) cfg.max_disasm_lines = std::stoi(kv["max_disasm_lines"]);
    if (kv.count("max_function_list")) cfg.max_function_list = std::stoi(kv["max_function_list"]);
    if (kv.count("max_bytes_read")) cfg.max_bytes_read = std::stoi(kv["max_bytes_read"]);

    // Theme settings
    if (kv.count("font_size")) cfg.font_size = std::stoi(kv["font_size"]);
    if (kv.count("dark_mode")) cfg.dark_mode = (kv["dark_mode"] != "false" && kv["dark_mode"] != "0");

    return cfg;
}

void save_config(const Config& cfg) {
    std::string path = config_file_path();

    std::ofstream out(path);
    if (!out.is_open()) return;

    out << "backend=" << (cfg.backend == Backend::OPENAI ? "openai" : "claude") << "\n";
    if (!cfg.api_key.empty())
        out << "api_key=" << cfg.api_key << "\n";
    if (!cfg.api_url.empty())
        out << "api_url=" << cfg.api_url << "\n";
    if (!cfg.model.empty())
        out << "model=" << cfg.model << "\n";
    out << "max_turns=" << cfg.max_turns << "\n";
    out << "max_tokens=" << cfg.max_tokens << "\n";
    out << "max_disasm_lines=" << cfg.max_disasm_lines << "\n";
    out << "max_function_list=" << cfg.max_function_list << "\n";
    out << "max_bytes_read=" << cfg.max_bytes_read << "\n";
    out << "font_size=" << cfg.font_size << "\n";
    out << "dark_mode=" << (cfg.dark_mode ? "true" : "false") << "\n";
}

// ---------------------------------------------------------------------------
// SetupDialog — local to this translation unit
// ---------------------------------------------------------------------------

class SetupDialog : public QDialog {
public:
    explicit SetupDialog(const Config& current, QWidget* parent = nullptr)
        : QDialog(parent)
    {
        setWindowTitle("IDA Chat Setup");
        Theme t = get_theme(current.dark_mode);
        setStyleSheet(QString::fromStdString(get_dialog_style(t)));
        setMinimumWidth(420);

        auto* form = new QFormLayout();
        form->setSpacing(10);
        form->setContentsMargins(16, 16, 16, 8);

        // Backend combo
        backend_combo_ = new QComboBox();
        backend_combo_->addItem("Claude (Anthropic)");
        backend_combo_->addItem("OpenAI-compatible (llama.cpp, etc.)");
        backend_combo_->setCurrentIndex(current.backend == Backend::OPENAI ? 1 : 0);
        form->addRow("Backend:", backend_combo_);

        // API Key
        api_key_edit_ = new QLineEdit();
        api_key_edit_->setEchoMode(QLineEdit::Password);
        api_key_edit_->setText(QString::fromStdString(current.api_key));
        api_key_label_ = new QLabel("Anthropic API Key:");
        form->addRow(api_key_label_, api_key_edit_);

        // API URL
        api_url_edit_ = new QLineEdit();
        api_url_edit_->setText(QString::fromStdString(current.api_url));
        api_url_label_ = new QLabel("API URL:");
        form->addRow(api_url_label_, api_url_edit_);

        // Model
        model_edit_ = new QLineEdit();
        model_edit_->setText(QString::fromStdString(current.model));
        form->addRow("Model:", model_edit_);

        // Theme combo
        theme_combo_ = new QComboBox();
        theme_combo_->addItem("Dark (Mocha)");
        theme_combo_->addItem("Light (Latte)");
        theme_combo_->setCurrentIndex(current.dark_mode ? 0 : 1);
        form->addRow("Theme:", theme_combo_);

        // Font size spinner
        font_size_spin_ = new QSpinBox();
        font_size_spin_->setRange(8, 24);
        font_size_spin_->setValue(current.font_size);
        font_size_spin_->setSuffix(" px");
        form->addRow("Font Size:", font_size_spin_);

        // Buttons
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
        buttons->button(QDialogButtonBox::Ok)->setDefault(true);
        connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
        connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

        auto* layout = new QVBoxLayout(this);
        layout->addLayout(form);
        layout->addSpacing(8);
        layout->addWidget(buttons);

        // Dynamic field updates when backend changes
        connect(backend_combo_, QOverload<int>::of(&QComboBox::currentIndexChanged),
                this, &SetupDialog::on_backend_changed);
        on_backend_changed(backend_combo_->currentIndex());
    }

    Config result() const {
        Config cfg;
        cfg.backend = backend_combo_->currentIndex() == 1 ? Backend::OPENAI : Backend::CLAUDE;
        cfg.api_key = api_key_edit_->text().trimmed().toStdString();
        cfg.api_url = api_url_edit_->text().trimmed().toStdString();
        cfg.model = model_edit_->text().trimmed().toStdString();
        cfg.dark_mode = (theme_combo_->currentIndex() == 0);
        cfg.font_size = font_size_spin_->value();
        return cfg;
    }

private:
    void on_backend_changed(int index) {
        bool openai = (index == 1);
        if (openai) {
            api_key_label_->setText("API Key (optional):");
            api_url_label_->setVisible(true);
            api_url_edit_->setVisible(true);
            api_url_edit_->setPlaceholderText("http://localhost:8080/v1/chat/completions");
            if (model_edit_->text().isEmpty() || model_edit_->text().startsWith("claude"))
                model_edit_->setText("qwen2.5-coder");
        } else {
            api_key_label_->setText("Anthropic API Key:");
            api_url_label_->setVisible(false);
            api_url_edit_->setVisible(false);
            if (model_edit_->text().isEmpty() || model_edit_->text() == "qwen2.5-coder")
                model_edit_->setText("claude-sonnet-4-20250514");
        }
    }

    QComboBox* backend_combo_;
    QLabel* api_key_label_;
    QLineEdit* api_key_edit_;
    QLabel* api_url_label_;
    QLineEdit* api_url_edit_;
    QLineEdit* model_edit_;
    QComboBox* theme_combo_;
    QSpinBox* font_size_spin_;
};

bool show_setup_dialog(Config& cfg) {
    SetupDialog dlg(cfg);
    if (dlg.exec() != QDialog::Accepted)
        return false;

    Config result = dlg.result();
    // Preserve non-dialog settings
    result.max_turns = cfg.max_turns;
    result.max_tokens = cfg.max_tokens;
    cfg = result;
    return true;
}

} // namespace ida_chat
