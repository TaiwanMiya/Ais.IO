#ifndef BINARY_WINDOW_H
#define BINARY_WINDOW_H

#include "codeeditor.h"
#include "../hexadecimal_editor/hexform.h"
#include "../hexadecimal_editor/hexview.h"

#include <QMainWindow>
#include <QPointer>
#include <QTimer>
#include <QFileDialog>
#include <QMessageBox>
#include <QGraphicsView>
#include <QGraphicsScene>

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
    HexView *hex;
    // QPointer<HexForm> hexform;
    QPointer<HexForm> hexform;
    // void loadBinary(const QByteArray& data);
};

#endif // BINARY_WINDOW_H
