#pragma once
#include <QMainWindow>
#include <QPointer>

class QTabWidget;
class QLineEdit;
class QTextEdit;
class QPushButton;
class QComboBox;
class QProgressBar;
class CryptoWorker;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

private slots:
    void onRunBaseEncode();
    void onRunBaseDecode();
    void onRunSymEncrypt();
    void onRunSymDecrypt();
    void onWorkerStarted();
    void onWorkerFinished(const QString& output, const QString& err, int exitCode);

private:
    void setupUi();
    QWidget* buildBaseTab();
    QWidget* buildSymTab();

    QTabWidget* tabs_{};

    // BASE
    QComboBox* cbBase_{};      // ← 統一使用 cbBase_
    QTextEdit* txtBaseIn_{};
    QTextEdit* txtBaseOut_{};
    QPushButton* btnBaseEnc_{};
    QPushButton* btnBaseDec_{};

    // 對稱加解密
    QComboBox* cbAlgo_{};
    QLineEdit* txtKey_{};
    QLineEdit* txtIv_{};
    QComboBox* cbKeyFmt_{};
    QComboBox* cbTextEnc_{};
    QTextEdit* txtSymIn_{};
    QTextEdit* txtSymOut_{};
    QPushButton* btnSymEnc_{};
    QPushButton* btnSymDec_{};

    QProgressBar* progress_{};
    QPointer<CryptoWorker> worker_;
};
