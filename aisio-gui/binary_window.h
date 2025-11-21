#ifndef BINARY_WINDOW_H
#define BINARY_WINDOW_H

#include "codeeditor.h"

#include <QMainWindow>
#include <QPointer>
#include <QTimer>
#include <QFileDialog>
#include <QMessageBox>

QT_BEGIN_NAMESPACE
namespace Ui { class BinaryWindow; }
QT_END_NAMESPACE

class BinaryWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit BinaryWindow(QWidget *parent = nullptr);
    ~BinaryWindow();

private:
    Ui::BinaryWindow *ui;
    CodeEditor *editor;
};

#endif // BINARY_WINDOW_H
