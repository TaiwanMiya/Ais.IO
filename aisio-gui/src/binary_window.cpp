#include "../include/binary_window.h"
#include "../text_editor/textview.h"
#include "ui_binary_window.h"

#include <QShortcut>

BinaryWindow::BinaryWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::BinaryWindow) {  // ← 初始化
    ui->setupUi(this);          // ← 建立 UI 元件

    TextView *editor = new TextView(this);
    editor->setSizePolicy(ui->plainTextEdit->sizePolicy());
    ui->horizontalLayout->replaceWidget(ui->plainTextEdit, editor);
    delete ui->plainTextEdit;
    ui->plainTextEdit = nullptr;
}

BinaryWindow::~BinaryWindow() {
    delete ui;   // 釋放記憶體
}
