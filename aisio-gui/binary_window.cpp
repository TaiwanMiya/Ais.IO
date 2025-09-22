#include "binary_window.h"
#include <ui_binary_window.h>

BinaryWindow::BinaryWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::BinaryWindow) {  // ← 初始化
    ui->setupUi(this);          // ← 建立 UI 元件
}

BinaryWindow::~BinaryWindow() {
    delete ui;   // 釋放記憶體
}
