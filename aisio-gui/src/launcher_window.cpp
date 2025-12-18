#include "../include/base_encoder_window.h"
#include "../include/launcher_window.h"
#include "ui_launcher_window.h"

LauncherWindow::LauncherWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::LauncherWindow) {    // ← 初始化
    ui->setupUi(this);          // ← 建立 UI 元件
}

LauncherWindow::~LauncherWindow() {
    delete ui;   // 釋放記憶體
}

void LauncherWindow::on_textEditorPushButton_clicked() {
    QMessageBox::warning(this, tr("Wrong"), "Not yet developed, please stay tuned!");
    return;
}

void LauncherWindow::on_hexadecimalEditorPushButton_clicked() {
    if (!hexform) {
        hexform = new HexForm(nullptr);
        hexform->setWindowFlag(Qt::Window, true);
        hexform->setAttribute(Qt::WA_DeleteOnClose);
    }
    hexform->showNormal();
    hexform->raise();
    hexform->activateWindow();
}

void LauncherWindow::on_baseEncoderPushButton_clicked() {
    if (!baseEncoderWin) {
        baseEncoderWin = new BaseEncoderWindow(nullptr);
        baseEncoderWin->setWindowFlag(Qt::Window, true);
        baseEncoderWin->setAttribute(Qt::WA_DeleteOnClose);
    }
    baseEncoderWin->showNormal();
    baseEncoderWin->raise();
    baseEncoderWin->activateWindow();
}

void LauncherWindow::on_binaryDataPushButton_clicked() {
    if (!binaryWin) {
        binaryWin = new BinaryWindow(nullptr);
        binaryWin->setWindowFlag(Qt::Window, true);
        binaryWin->setAttribute(Qt::WA_DeleteOnClose);
    }
    binaryWin->showNormal();
    binaryWin->raise();
    binaryWin->activateWindow();
}

void LauncherWindow::on_aesPushButton_clicked() {
    QMessageBox::warning(this, tr("Wrong"), "Not yet developed, please stay tuned!");
    return;
}

void LauncherWindow::on_desPushButton_clicked() {
    QMessageBox::warning(this, tr("Wrong"), "Not yet developed, please stay tuned!");
    return;
}

void LauncherWindow::on_dsaPushButton_clicked() {
    QMessageBox::warning(this, tr("Wrong"), "Not yet developed, please stay tuned!");
    return;
}

void LauncherWindow::on_rsaPushButton_clicked() {
    QMessageBox::warning(this, tr("Wrong"), "Not yet developed, please stay tuned!");
    return;
}

void LauncherWindow::on_eccPushButton_clicked() {
    QMessageBox::warning(this, tr("Wrong"), "Not yet developed, please stay tuned!");
    return;
}
