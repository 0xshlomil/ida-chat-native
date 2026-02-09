#pragma once

#include <QWidget>
#include <QTextBrowser>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QTimer>
#include <memory>

#include "config.h"

namespace ida_chat {

class WorkerThread;
class ToolExecutor;

class ChatWidget : public QWidget {
    Q_OBJECT

public:
    explicit ChatWidget(QWidget* parent = nullptr);
    ~ChatWidget() override;

private slots:
    void on_send_clicked();
    void on_cancel_clicked();
    void on_clear_clicked();
    void on_settings_clicked();
    void on_text_received(const QString& text);
    void on_tool_called(const QString& tool_name, const QString& input_summary);
    void on_tool_result_received(const QString& tool_name, const QString& result_summary);
    void on_thinking(bool is_thinking);
    void on_error_occurred(const QString& error);
    void on_finished_processing();
    void on_blink_timer();

protected:
    bool eventFilter(QObject* obj, QEvent* event) override;

private:
    void setup_ui();
    void apply_theme();
    void connect_worker();
    void append_user_message(const QString& text);
    void append_html(const QString& html);
    void set_processing(bool processing);
    void scroll_to_bottom();

    // UI components
    QLabel* header_ = nullptr;
    QTextBrowser* chat_display_ = nullptr;
    QPlainTextEdit* input_edit_ = nullptr;
    QPushButton* send_button_ = nullptr;
    QPushButton* cancel_button_ = nullptr;
    QPushButton* clear_button_ = nullptr;
    QPushButton* settings_button_ = nullptr;
    QLabel* status_label_ = nullptr;
    QTimer* blink_timer_ = nullptr;

    // State
    bool processing_ = false;
    bool blink_state_ = false;
    QString current_assistant_text_;  // accumulate text for current response

    // Components
    Config config_;
    std::unique_ptr<ToolExecutor> executor_;
    std::unique_ptr<WorkerThread> worker_;
};

} // namespace ida_chat
