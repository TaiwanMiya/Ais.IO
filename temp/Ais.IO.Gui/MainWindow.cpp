#include "MainWindow.h"
#include "CryptoWorker.h"

#include <QApplication>
#include <QTabWidget>
#include <QGridLayout>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QComboBox>
#include <QLineEdit>
#include <QTextEdit>
#include <QPushButton>
#include <QProgressBar>
#include <QMessageBox>
#include <QJsonObject>
#include <QJsonDocument>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setupUi();
    setWindowTitle("Ais.IO Tools");
    resize(980, 720);
}

void MainWindow::setupUi() {
    tabs_ = new QTabWidget(this);
    tabs_->addTab(buildBaseTab(), "BASE 編碼");
    tabs_->addTab(buildSymTab(), "對稱加解密");

    progress_ = new QProgressBar(this);
    progress_->setRange(0, 0);
    progress_->setVisible(false);

    auto* central = new QWidget(this);
    auto* v = new QVBoxLayout(central);
    v->addWidget(tabs_);
    v->addWidget(progress_);
    setCentralWidget(central);
}

QWidget* MainWindow::buildBaseTab() {
    auto* page = new QWidget(this);
    auto* grid = new QGridLayout(page);

    cbBase_ = new QComboBox(page); // ← 修正命名
    cbBase_->addItems({ "BASE10","BASE16","BASE32","BASE58","BASE62","BASE64","BASE85","BASE91" });

    txtBaseIn_ = new QTextEdit(page);
    txtBaseOut_ = new QTextEdit(page);
    txtBaseOut_->setReadOnly(true);

    btnBaseEnc_ = new QPushButton("編碼", page);
    btnBaseDec_ = new QPushButton("解碼", page);

    connect(btnBaseEnc_, &QPushButton::clicked, this, &MainWindow::onRunBaseEncode);
    connect(btnBaseDec_, &QPushButton::clicked, this, &MainWindow::onRunBaseDecode);

    int r = 0;
    grid->addWidget(new QLabel("類型:"), r, 0); grid->addWidget(cbBase_, r, 1);
    r++;
    grid->addWidget(new QLabel("輸入:"), r, 0); grid->addWidget(txtBaseIn_, r, 1, 2, 1);
    r += 2;
    grid->addWidget(new QLabel("輸出:"), r, 0); grid->addWidget(txtBaseOut_, r, 1, 2, 1);
    r += 2;

    auto* h = new QHBoxLayout();
    h->addWidget(btnBaseEnc_);
    h->addWidget(btnBaseDec_);
    grid->addLayout(h, r, 1);

    return page;
}

QWidget* MainWindow::buildSymTab() {
    auto* page = new QWidget(this);
    auto* form = new QFormLayout(page);

    cbAlgo_ = new QComboBox(page);
    cbAlgo_->addItems({ "AES-CTR","AES-CBC","AES-CFB","AES-OFB","AES-GCM" });

    txtKey_ = new QLineEdit(page);
    txtIv_ = new QLineEdit(page);

    cbKeyFmt_ = new QComboBox(page);
    cbKeyFmt_->addItems({ "Base64","Hex","Raw" });

    cbTextEnc_ = new QComboBox(page);
    cbTextEnc_->addItems({ "UTF8","ASCII" });

    txtSymIn_ = new QTextEdit(page);
    txtSymOut_ = new QTextEdit(page);
    txtSymOut_->setReadOnly(true);

    btnSymEnc_ = new QPushButton("加密", page);
    btnSymDec_ = new QPushButton("解密", page);

    connect(btnSymEnc_, &QPushButton::clicked, this, &MainWindow::onRunSymEncrypt);
    connect(btnSymDec_, &QPushButton::clicked, this, &MainWindow::onRunSymDecrypt);

    form->addRow("演算法:", cbAlgo_);
    form->addRow("Key:", txtKey_);
    form->addRow("IV/Nonce:", txtIv_);
    form->addRow("Key 格式:", cbKeyFmt_);
    form->addRow("文字編碼:", cbTextEnc_);
    form->addRow("輸入:", txtSymIn_);
    form->addRow("輸出:", txtSymOut_);

    auto* h = new QHBoxLayout();
    h->addWidget(btnSymEnc_);
    h->addWidget(btnSymDec_);
    form->addRow(h);

    return page;
}

void MainWindow::onWorkerStarted() {
    progress_->setVisible(true);
}

void MainWindow::onWorkerFinished(const QString& output, const QString& err, int /*exitCode*/) {
    progress_->setVisible(false);
    if (!err.isEmpty())
        QMessageBox::warning(this, "Ais.IO", err);

    if (tabs_->currentIndex() == 0) {
        txtBaseOut_->setPlainText(output);
    }
    else {
        txtSymOut_->setPlainText(output);
    }
}

void MainWindow::onRunBaseEncode() {
    const auto mode = cbBase_->currentText();
    const auto input = txtBaseIn_->toPlainText();

    QStringList args{ "BaseEncode", input };
    args << "--type" << mode;

    if (worker_) worker_->deleteLater();
    worker_ = new CryptoWorker(this);
    connect(worker_, &CryptoWorker::started, this, &MainWindow::onWorkerStarted);
    connect(worker_, &CryptoWorker::finished, this, &MainWindow::onWorkerFinished);
    worker_->runAisio(args);
}

void MainWindow::onRunBaseDecode() {
    const auto mode = cbBase_->currentText();
    const auto input = txtBaseIn_->toPlainText();

    QStringList args{ "BaseDecode", input };
    args << "--type" << mode;

    if (worker_) worker_->deleteLater();
    worker_ = new CryptoWorker(this);
    connect(worker_, &CryptoWorker::started, this, &MainWindow::onWorkerStarted);
    connect(worker_, &CryptoWorker::finished, this, &MainWindow::onWorkerFinished);
    worker_->runAisio(args);
}

void MainWindow::onRunSymEncrypt() {
    const auto algo = cbAlgo_->currentText();
    const auto key = txtKey_->text();
    const auto iv = txtIv_->text();
    const auto kfmt = cbKeyFmt_->currentText();
    const auto enc = cbTextEnc_->currentText();
    const auto input = txtSymIn_->toPlainText();

    QString apiName;
    if (algo == "AES-CTR") apiName = "AesCtrEncrypt";
    else if (algo == "AES-CBC") apiName = "AesCbcEncrypt";
    else if (algo == "AES-CFB") apiName = "AesCfbEncrypt";
    else if (algo == "AES-OFB") apiName = "AesOfbEncrypt";
    else if (algo == "AES-GCM") apiName = "AesGcmEncrypt";

    QJsonObject obj{
        {"key",       key},
        {"iv",        iv},
        {"size",      256},
        {"keyformat", kfmt},
        {"decode",    true},
        {"content",   input},
        {"encoding",  enc},
        {"format",    "Base64"},
        {"errors",    "ignore"}
    };

    if (worker_) worker_->deleteLater();
    worker_ = new CryptoWorker(this);
    connect(worker_, &CryptoWorker::started, this, &MainWindow::onWorkerStarted);
    connect(worker_, &CryptoWorker::finished, this, &MainWindow::onWorkerFinished);
    worker_->runAisioJson(apiName, QJsonDocument(obj).toJson(QJsonDocument::Compact));
}

void MainWindow::onRunSymDecrypt() {
    const auto algo = cbAlgo_->currentText();
    const auto key = txtKey_->text();
    const auto iv = txtIv_->text();
    const auto kfmt = cbKeyFmt_->currentText();
    const auto enc = cbTextEnc_->currentText();
    const auto input = txtSymIn_->toPlainText();

    QString apiName;
    if (algo == "AES-CTR") apiName = "AesCtrDecrypt";
    else if (algo == "AES-CBC") apiName = "AesCbcDecrypt";
    else if (algo == "AES-CFB") apiName = "AesCfbDecrypt";
    else if (algo == "AES-OFB") apiName = "AesOfbDecrypt";
    else if (algo == "AES-GCM") apiName = "AesGcmDecrypt";

    QJsonObject obj{
        {"key",       key},
        {"iv",        iv},
        {"size",      256},
        {"keyformat", kfmt},
        {"decode",    true},
        {"content",   input},
        {"encoding",  enc},
        {"format",    "Base64"},
        {"errors",    "ignore"}
    };

    if (worker_) worker_->deleteLater();
    worker_ = new CryptoWorker(this);
    connect(worker_, &CryptoWorker::started, this, &MainWindow::onWorkerStarted);
    connect(worker_, &CryptoWorker::finished, this, &MainWindow::onWorkerFinished);
    worker_->runAisioJson(apiName, QJsonDocument(obj).toJson(QJsonDocument::Compact));
}
