#include "chat_widget.h"
#include "worker_thread.h"
#include "tool_executor.h"

#include <QKeyEvent>
#include <QHBoxLayout>
#include <QScrollBar>
#include <QApplication>
#include <QRegularExpression>

namespace ida_chat {

// Minimal markdown-to-HTML: code blocks, inline code, bold, italic, headers
static QString markdown_to_html(const QString& md, const Theme& t, int font_size) {
    QString result;
    QStringList lines = md.split('\n');
    bool in_code_block = false;
    int code_font = font_size - 1;

    for (const QString& line : lines) {
        if (line.startsWith("```")) {
            if (in_code_block) {
                result += "</pre>";
                in_code_block = false;
            } else {
                result += QString("<pre style='background:%1;color:%2;padding:8px;border-radius:4px;"
                                  "font-family:monospace;font-size:%3px;white-space:pre-wrap;'>")
                    .arg(t.base, t.text).arg(code_font);
                in_code_block = true;
            }
            continue;
        }

        if (in_code_block) {
            // Escape HTML in code blocks
            QString escaped = line.toHtmlEscaped();
            result += escaped + "\n";
            continue;
        }

        QString processed = line;

        // Headers
        if (processed.startsWith("### ")) {
            processed = "<h4>" + processed.mid(4).toHtmlEscaped() + "</h4>";
        } else if (processed.startsWith("## ")) {
            processed = "<h3>" + processed.mid(3).toHtmlEscaped() + "</h3>";
        } else if (processed.startsWith("# ")) {
            processed = "<h2>" + processed.mid(2).toHtmlEscaped() + "</h2>";
        } else {
            // Escape HTML first
            processed = processed.toHtmlEscaped();

            // Inline code (backticks)
            QRegularExpression code_re("`([^`]+)`");
            processed.replace(code_re,
                QString("<code style='background:%1;color:%2;padding:1px 4px;border-radius:3px;font-family:monospace;'>\\1</code>")
                    .arg(t.surface0, t.text));

            // Bold
            QRegularExpression bold_re("\\*\\*([^*]+)\\*\\*");
            processed.replace(bold_re, "<b>\\1</b>");

            // Italic
            QRegularExpression italic_re("\\*([^*]+)\\*");
            processed.replace(italic_re, "<i>\\1</i>");

            // Bullet points
            if (processed.startsWith("- ") || processed.startsWith("* ")) {
                processed = "&bull; " + processed.mid(2);
            }

            processed += "<br>";
        }

        result += processed;
    }

    if (in_code_block) {
        result += "</pre>";
    }

    return result;
}

ChatWidget::ChatWidget(QWidget* parent)
    : QWidget(parent)
{
    setup_ui();

    // Load config
    config_ = load_config();

    // Apply theme from loaded config
    apply_theme();

    // Create executor on main thread
    executor_ = std::make_unique<ToolExecutor>(config_, this);

    // Show setup dialog if unconfigured (Claude needs a key; OpenAI can work without one)
    bool needs_setup = config_.api_key.empty() && config_.backend == Backend::CLAUDE;
    if (needs_setup) {
        if (show_setup_dialog(config_)) {
            save_config(config_);
            apply_theme();
        }
    }

    Theme t = get_theme(config_.dark_mode);
    bool configured = !config_.api_key.empty() || config_.backend == Backend::OPENAI;
    if (configured) {
        worker_ = std::make_unique<WorkerThread>(executor_.get(), config_, this);
        connect_worker();
        status_label_->setText("Ready");
        status_label_->setStyleSheet(QString("color: %1;").arg(t.green));
    } else {
        status_label_->setText("Not configured — click \xe2\x9a\x99 to set up");
        status_label_->setStyleSheet(QString("color: %1;").arg(t.red));
        send_button_->setEnabled(false);
    }
}

ChatWidget::~ChatWidget() {
    if (worker_) {
        worker_->cancel();
        worker_->wait();
    }
}

void ChatWidget::setup_ui() {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(4, 4, 4, 4);
    layout->setSpacing(4);

    // Header with settings button
    auto* header_layout = new QHBoxLayout();
    header_layout->setContentsMargins(0, 0, 0, 0);
    header_ = new QLabel("<b>IDA Chat</b> (Native)");
    header_layout->addWidget(header_);
    header_layout->addStretch();

    settings_button_ = new QPushButton("\xe2\x9a\x99", this);
    settings_button_->setFixedSize(28, 28);
    settings_button_->setToolTip("Settings");
    connect(settings_button_, &QPushButton::clicked, this, &ChatWidget::on_settings_clicked);
    header_layout->addWidget(settings_button_);

    layout->addLayout(header_layout);

    // Chat display
    chat_display_ = new QTextBrowser(this);
    chat_display_->setOpenExternalLinks(true);
    layout->addWidget(chat_display_, 1);

    // Status label
    status_label_ = new QLabel("Initializing...");
    layout->addWidget(status_label_);

    // Input area
    input_edit_ = new QPlainTextEdit(this);
    input_edit_->setPlaceholderText("Ask about the binary... (Enter to send, Shift+Enter for newline)");
    input_edit_->setMaximumHeight(80);
    input_edit_->installEventFilter(this);
    layout->addWidget(input_edit_);

    // Buttons
    auto* button_layout = new QHBoxLayout();
    button_layout->setSpacing(4);

    send_button_ = new QPushButton("Send", this);
    connect(send_button_, &QPushButton::clicked, this, &ChatWidget::on_send_clicked);
    button_layout->addWidget(send_button_);

    cancel_button_ = new QPushButton("Cancel", this);
    cancel_button_->setVisible(false);
    connect(cancel_button_, &QPushButton::clicked, this, &ChatWidget::on_cancel_clicked);
    button_layout->addWidget(cancel_button_);

    clear_button_ = new QPushButton("Clear", this);
    connect(clear_button_, &QPushButton::clicked, this, &ChatWidget::on_clear_clicked);
    button_layout->addWidget(clear_button_);

    button_layout->addStretch();
    layout->addLayout(button_layout);

    // Blink timer for processing indicator
    blink_timer_ = new QTimer(this);
    blink_timer_->setInterval(500);
    connect(blink_timer_, &QTimer::timeout, this, &ChatWidget::on_blink_timer);
}

void ChatWidget::apply_theme() {
    Theme t = get_theme(config_.dark_mode);
    int fs = config_.font_size;

    setStyleSheet(QString("background-color: %1;").arg(t.mantle));

    header_->setStyleSheet(QString("color: %1; font-size: %2px; padding: 4px;").arg(t.text).arg(fs + 1));

    settings_button_->setStyleSheet(
        QString("QPushButton {"
                "  background-color: transparent; color: %1; border: none;"
                "  font-size: 16px;"
                "}"
                "QPushButton:hover { color: %2; }")
            .arg(t.overlay0, t.text));

    chat_display_->setStyleSheet(
        QString("QTextBrowser {"
                "  background-color: %1;"
                "  color: %2;"
                "  border: 1px solid %3;"
                "  border-radius: 4px;"
                "  padding: 8px;"
                "  font-size: %4px;"
                "}")
            .arg(t.base, t.text, t.surface1).arg(fs));

    status_label_->setStyleSheet(QString("color: %1; font-size: %2px; padding: 2px;").arg(t.overlay0).arg(fs - 2));

    input_edit_->setStyleSheet(
        QString("QPlainTextEdit {"
                "  background-color: %1;"
                "  color: %2;"
                "  border: 1px solid %3;"
                "  border-radius: 4px;"
                "  padding: 6px;"
                "  font-size: %4px;"
                "}")
            .arg(t.surface0, t.text, t.surface1).arg(fs));

    send_button_->setStyleSheet(
        QString("QPushButton {"
                "  background-color: %1;"
                "  color: %2;"
                "  border: none;"
                "  border-radius: 4px;"
                "  padding: 6px 16px;"
                "  font-weight: bold;"
                "}"
                "QPushButton:hover { background-color: %3; }"
                "QPushButton:disabled { background-color: %4; color: %5; }")
            .arg(t.blue, t.base, t.sapphire, t.surface1, t.overlay0));

    cancel_button_->setStyleSheet(
        QString("QPushButton {"
                "  background-color: %1;"
                "  color: %2;"
                "  border: none;"
                "  border-radius: 4px;"
                "  padding: 6px 16px;"
                "  font-weight: bold;"
                "}"
                "QPushButton:hover { background-color: %3; }")
            .arg(t.red, t.base, t.pink));

    clear_button_->setStyleSheet(
        QString("QPushButton {"
                "  background-color: %1;"
                "  color: %2;"
                "  border: none;"
                "  border-radius: 4px;"
                "  padding: 6px 16px;"
                "}"
                "QPushButton:hover { background-color: %3; }")
            .arg(t.surface1, t.text, t.surface2));
}

void ChatWidget::connect_worker() {
    connect(worker_.get(), &WorkerThread::text_received,
            this, &ChatWidget::on_text_received);
    connect(worker_.get(), &WorkerThread::tool_called,
            this, &ChatWidget::on_tool_called);
    connect(worker_.get(), &WorkerThread::tool_result_received,
            this, &ChatWidget::on_tool_result_received);
    connect(worker_.get(), &WorkerThread::thinking,
            this, &ChatWidget::on_thinking);
    connect(worker_.get(), &WorkerThread::error_occurred,
            this, &ChatWidget::on_error_occurred);
    connect(worker_.get(), &WorkerThread::finished_processing,
            this, &ChatWidget::on_finished_processing);
}

bool ChatWidget::eventFilter(QObject* obj, QEvent* event) {
    if (obj == input_edit_ && event->type() == QEvent::KeyPress) {
        auto* key_event = static_cast<QKeyEvent*>(event);

        // Enter sends, Shift+Enter inserts newline
        if (key_event->key() == Qt::Key_Return || key_event->key() == Qt::Key_Enter) {
            if (key_event->modifiers() & Qt::ShiftModifier) {
                return false;  // Allow default newline behavior
            }
            on_send_clicked();
            return true;
        }

        // Escape cancels
        if (key_event->key() == Qt::Key_Escape && processing_) {
            on_cancel_clicked();
            return true;
        }
    }
    return QWidget::eventFilter(obj, event);
}

void ChatWidget::on_send_clicked() {
    if (processing_ || !worker_) return;

    QString text = input_edit_->toPlainText().trimmed();
    if (text.isEmpty()) return;

    input_edit_->clear();
    append_user_message(text);
    set_processing(true);

    current_assistant_text_.clear();
    worker_->send_message(text);
}

void ChatWidget::on_cancel_clicked() {
    if (worker_) {
        worker_->cancel();
    }
}

void ChatWidget::on_clear_clicked() {
    chat_display_->clear();
    if (worker_) {
        worker_->clear_history();
    }
    current_assistant_text_.clear();
}

void ChatWidget::on_settings_clicked() {
    if (processing_) return;

    if (!show_setup_dialog(config_)) return;
    save_config(config_);

    // Re-apply theme (colors/font may have changed)
    apply_theme();

    // Update executor config (tool limits may have changed)
    executor_->update_config(config_);

    // Recreate worker with new config
    if (worker_) {
        worker_->cancel();
        worker_->wait();
        worker_.reset();
    }

    Theme t = get_theme(config_.dark_mode);
    bool configured = !config_.api_key.empty() || config_.backend == Backend::OPENAI;
    if (configured) {
        worker_ = std::make_unique<WorkerThread>(executor_.get(), config_, this);
        connect_worker();
        status_label_->setText("Ready");
        status_label_->setStyleSheet(QString("color: %1;").arg(t.green));
        send_button_->setEnabled(true);
    } else {
        status_label_->setText("Not configured \xe2\x80\x94 click \xe2\x9a\x99 to set up");
        status_label_->setStyleSheet(QString("color: %1;").arg(t.red));
        send_button_->setEnabled(false);
    }
}

void ChatWidget::on_text_received(const QString& text) {
    current_assistant_text_ += text;
    // Re-render accumulated text as markdown
    Theme t = get_theme(config_.dark_mode);
    QString html =
        QString("<div style='margin:8px 0;padding:8px;background:%1;border-radius:6px;border-left:3px solid %2;'>")
            .arg(t.surface0, t.blue)
        + markdown_to_html(current_assistant_text_, t, config_.font_size) +
        "</div>";

    // Replace last assistant block or append
    // For simplicity, we append the full response at finish_processing
    // During streaming we just update status
    status_label_->setText("Receiving response...");
}

void ChatWidget::on_tool_called(const QString& tool_name, const QString& input_summary) {
    Theme t = get_theme(config_.dark_mode);
    int tool_fs = config_.font_size - 2;
    QString html = QString(
        "<div style='margin:4px 0;padding:4px 8px;color:%1;font-size:%2px;'>"
        "&#128295; <b>%3</b>(%4)"
        "</div>"
    ).arg(t.subtext).arg(tool_fs).arg(tool_name.toHtmlEscaped(), input_summary.toHtmlEscaped().left(100));
    append_html(html);
}

void ChatWidget::on_tool_result_received(const QString& tool_name, const QString& result_summary) {
    Q_UNUSED(tool_name);
    Q_UNUSED(result_summary);
    // Tool results are fed back to the agent, no need to show raw JSON to user
    status_label_->setText("Processing tool results...");
}

void ChatWidget::on_thinking(bool is_thinking) {
    if (is_thinking) {
        status_label_->setText("Thinking...");
        blink_timer_->start();
    }
}

void ChatWidget::on_error_occurred(const QString& error) {
    Theme t = get_theme(config_.dark_mode);
    QString html = QString(
        "<div style='margin:8px 0;padding:8px;background:%1;border-radius:6px;border-left:3px solid %2;color:%2;'>"
        "<b>Error:</b> %3"
        "</div>"
    ).arg(t.surface1, t.red, error.toHtmlEscaped());
    append_html(html);
}

void ChatWidget::on_finished_processing() {
    // Render final accumulated assistant text
    if (!current_assistant_text_.isEmpty()) {
        Theme t = get_theme(config_.dark_mode);
        QString html =
            QString("<div style='margin:8px 0;padding:8px;background:%1;border-radius:6px;border-left:3px solid %2;'>")
                .arg(t.surface0, t.blue)
            + markdown_to_html(current_assistant_text_, t, config_.font_size) +
            "</div>";
        append_html(html);
    }
    current_assistant_text_.clear();
    set_processing(false);
    Theme t = get_theme(config_.dark_mode);
    status_label_->setText("Ready");
    status_label_->setStyleSheet(QString("color: %1;").arg(t.green));
    blink_timer_->stop();
}

void ChatWidget::on_blink_timer() {
    Theme t = get_theme(config_.dark_mode);
    blink_state_ = !blink_state_;
    if (blink_state_) {
        status_label_->setStyleSheet(QString("color: %1;").arg(t.peach));   // orange
    } else {
        status_label_->setStyleSheet(QString("color: %1;").arg(t.surface1)); // dim
    }
}

void ChatWidget::append_user_message(const QString& text) {
    Theme t = get_theme(config_.dark_mode);
    QString html = QString(
        "<div style='margin:8px 0;padding:8px;background:%1;border-radius:6px;border-left:3px solid %2;'>"
        "<b style='color:%2;'>You:</b> %3"
        "</div>"
    ).arg(t.surface1, t.green, text.toHtmlEscaped());
    append_html(html);
}

void ChatWidget::append_html(const QString& html) {
    QTextCursor cursor = chat_display_->textCursor();
    cursor.movePosition(QTextCursor::End);
    cursor.insertHtml(html);
    scroll_to_bottom();
}

void ChatWidget::set_processing(bool processing) {
    processing_ = processing;
    send_button_->setVisible(!processing);
    cancel_button_->setVisible(processing);
    input_edit_->setEnabled(!processing);
    if (!processing) {
        input_edit_->setFocus();
    }
}

void ChatWidget::scroll_to_bottom() {
    QScrollBar* sb = chat_display_->verticalScrollBar();
    sb->setValue(sb->maximum());
}

} // namespace ida_chat
