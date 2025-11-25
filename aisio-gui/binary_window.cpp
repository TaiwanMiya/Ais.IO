#include "binary_window.h"
#include "codeeditor.h"
#include "hexview.h"
#include <ui_binary_window.h>

BinaryWindow::BinaryWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::BinaryWindow) {  // ← 初始化
    ui->setupUi(this);          // ← 建立 UI 元件

    // CodeEditor *editor = new CodeEditor(this);
    // editor->setSizePolicy(ui->plainTextEdit->sizePolicy());
    // ui->horizontalLayout->replaceWidget(ui->plainTextEdit, editor);
    // delete ui->plainTextEdit;
    // ui->plainTextEdit = nullptr;

    QByteArray arr("Hello world! And i fuck you bitch!!! HAHAHA ><\n ??? OK... You're hilarious.");
    arr.append(QByteArray::fromHex("DEADBEEF"));
    arr.append("OkOk");

    hex = new HexView(this);
    ui->horizontalLayout->addWidget(hex);

    // 測試資料
    hex->loadData(arr);
    // hex->setEditable(true);
}

BinaryWindow::~BinaryWindow() {
    delete ui;   // 釋放記憶體
}
