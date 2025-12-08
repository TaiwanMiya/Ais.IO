#include "../include/binary_window.h"
#include "../include/codeeditor.h"
#include "ui_binary_window.h"

#include <QShortcut>

BinaryWindow::BinaryWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::BinaryWindow) {  // ← 初始化
    ui->setupUi(this);          // ← 建立 UI 元件

    // CodeEditor *editor = new CodeEditor(this);
    // editor->setSizePolicy(ui->plainTextEdit->sizePolicy());
    // ui->horizontalLayout->replaceWidget(ui->plainTextEdit, editor);
    // delete ui->plainTextEdit;
    // ui->plainTextEdit = nullptr;

    // QByteArray arr("Hello world! And i fuck you bitch!!! HAHAHA ><\n ??? OK... You're hilarious.");
    // arr.append(QByteArray::fromHex("DEADBEEF"));
    // arr.append("OkOk");

    QByteArray arr;
#ifdef _WIN32
    QFile file("C:\\Users\\User\\Documents\\Ais.IO\\etest.bin");
#else
    QFile file("home/ais/Ais.IO/etest.bin");
#endif
    if (file.open(QIODevice::ReadOnly)) {
        arr = file.readAll();
        qDebug() << arr.length();
        file.close();
    }

    if (!hexform){
        hexform = new HexForm(arr, this, true);
        hexform->setWindowFlag(Qt::Window, true);
        hexform->setAttribute(Qt::WA_DeleteOnClose);
    }
    hexform->showNormal();
    hexform->raise();
    hexform->activateWindow();
}

BinaryWindow::~BinaryWindow() {
    delete ui;   // 釋放記憶體
}
