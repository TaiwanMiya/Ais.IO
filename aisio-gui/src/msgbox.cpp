#include "../include/msgbox.h"

MsgBox::MsgBox(QWidget *parent, QMessageBox::Icon icon)
    : QMessageBox(parent) {

    switch (icon) {
    case QMessageBox::Icon::NoIcon:
        this->setIcon(QMessageBox::NoIcon);
        break;
    case QMessageBox::Icon::Critical:
        this->setIcon(QMessageBox::Critical);
        break;
    case QMessageBox::Icon::Information:
        this->setIcon(QMessageBox::Information);
        break;
    case QMessageBox::Icon::Question:
        this->setIcon(QMessageBox::Question);
        break;
    case QMessageBox::Icon::Warning:
        this->setIcon(QMessageBox::Warning);
        break;
    }
}

MsgBox::~MsgBox() {

}

void MsgBox::show(const QString title, const QString text) {
    this->setIcon(QMessageBox::Critical);
    this->setWindowTitle(title);
    this->setText(text);
    this->setStyleSheet("* { background:#222222; color:#f0f0f0; }");
    this->exec();
}
