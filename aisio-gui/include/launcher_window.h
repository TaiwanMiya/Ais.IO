#ifndef LAUNCHER_WINDOW_H
#define LAUNCHER_WINDOW_H

#include "base_encoder_window.h"
#include "binary_window.h"

#include <QMainWindow>
#include <QPointer>
#include <BaseEncoderIO.h>
#include <QTimer>
#include <QFileDialog>
#include <QMessageBox>

QT_BEGIN_NAMESPACE
namespace Ui { class LauncherWindow; }
QT_END_NAMESPACE

class QProcess;
class BaseEncoderWindow;
class BinaryWindow;

class LauncherWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit LauncherWindow(QWidget *parent = nullptr);
    ~LauncherWindow();


private slots:
    void on_textEditorPushButton_clicked();
    void on_hexadecimalEditorPushButton_clicked();
    void on_baseEncoderPushButton_clicked();
    void on_binaryDataPushButton_clicked();
    void on_aesPushButton_clicked();
    void on_desPushButton_clicked();
    void on_dsaPushButton_clicked();
    void on_rsaPushButton_clicked();
    void on_eccPushButton_clicked();

private:
    Ui::LauncherWindow *ui;
    QPointer<HexForm> hexform;
    QPointer<BaseEncoderWindow> baseEncoderWin;
    QPointer<BinaryWindow> binaryWin;
};

#endif // LAUNCHER_WINDOW_H
