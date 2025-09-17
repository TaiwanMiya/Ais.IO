#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPointer>
#include <BaseEncoderIO.h>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class QProcess;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_encodeButton_clicked();   // 對應 encodeButton
    void on_decodeButton_clicked();   // 對應 decodeButton

private:
    Ui::MainWindow *ui;

    // 小工具：依下拉選單回傳一組函式指標
    struct BaseFns {
        size_t (*len)(size_t, bool) = nullptr;
        int (*enc)(const unsigned char*, size_t, char*, size_t) = nullptr;
        int (*dec)(const char*, size_t, unsigned char*, size_t) = nullptr;
    };
    BaseFns selectBaseFns(const QString& mode) const;
};

#endif // MAINWINDOW_H
