#ifndef BASE_ENCODER_WINDOW_H
#define BASE_ENCODER_WINDOW_H

#include <QMainWindow>
#include <QPointer>
#include <BaseEncoderIO.h>
#include <QTimer>
#include <QFileDialog>
#include <QMessageBox>
#include <QSaveFile>
#include <QThread>
#include <QProgressDialog>
#include <QElapsedTimer>

QT_BEGIN_NAMESPACE
namespace Ui { class BaseEncoderWindow; }
QT_END_NAMESPACE

class QProcess;

class BaseEncoderWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit BaseEncoderWindow(QWidget *parent = nullptr);
    ~BaseEncoderWindow();

private slots:
    void on_baseEncodeButton_clicked();             // 對應 baseEncodeButton
    void on_baseDecodeButton_clicked();             // 對應 baseDecodeButton
    void on_encodeToolButton_clicked();             // 對應 encodeToolButton
    void on_decodeToolButton_clicked();             // 對應 decodeToolButton
    void on_basePlainText_textChanged();            // 對應 basePlainText
    void on_baseCipherText_textChanged();           // 對應 baseCipherText
    void on_plainTextOutputToolButton_clicked();    // 對應 plainTextOutputToolButton
    void on_cipherTextOutputToolButton_clicked();   // 對應 cipherTextOutputToolButton

private:
    Ui::BaseEncoderWindow *ui;

    QByteArray m_plainBuffer;   // 左側：若由檔案導入，存放完整原始 bytes
    QString    m_plainPath;
    bool       m_plainFromFile = false;

    QByteArray m_cipherBuffer;  // 右側：若由檔案導入，存放完整 BaseN 字串（或原文 bytes，看你的檔內容）
    QString    m_cipherPath;
    bool       m_cipherFromFile = false;

    // 小工具：依下拉選單回傳一組函式指標
    struct BaseFns {
        size_t (*len)(size_t, bool) = nullptr;
        int (*enc)(const unsigned char*, size_t, char*, size_t) = nullptr;
        int (*dec)(const char*, size_t, unsigned char*, size_t) = nullptr;
    };
    BaseFns selectBaseFns(const QString& mode) const;
    void processErrorCode(const int& n);
};

#endif // BASE_ENCODER_WINDOW_H
