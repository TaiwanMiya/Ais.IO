// #include "mainwindow.h"
// #include "./ui_mainwindow.h"

// MainWindow::MainWindow(QWidget *parent)
//     : QMainWindow(parent)
//     , ui(new Ui::MainWindow)
// {
//     ui->setupUi(this);
// }

// MainWindow::~MainWindow()
// {
//     delete ui;
// }

#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QProcess>
#include <QJsonObject>
#include <QJsonDocument>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow) {
    ui->setupUi(this);

    // 初始化 Base 下拉選單
    if (ui->modeComboBox->count() == 0) {
        ui->modeComboBox->addItems(
            {"Base10","Base16","Base32","Base58","Base62","Base64","Base85","Base91"});
    }
    ui->cipherText->setReadOnly(true);
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::on_encodeButton_clicked() {
    const QString type = ui->modeComboBox->currentText();
    const QString text = ui->plainText->toPlainText();

    QJsonObject obj{
        {"type",     type},
        {"content",  text},
        {"encoding", "UTF8"}
    };
    callAisioJson("BaseEncode", obj);
}

void MainWindow::on_decodeButton_clicked() {
    const QString type = ui->modeComboBox->currentText();
    const QString text = ui->plainText->toPlainText();

    QJsonObject obj{
        {"type",     type},
        {"content",  text},
        {"encoding", "UTF8"}
    };
    callAisioJson("BaseDecode", obj);
}

void MainWindow::callAisioJson(const QString& apiName, const QJsonObject& payload) {
    if (proc_) { proc_->kill(); proc_->deleteLater(); }

    proc_ = new QProcess(this);
    proc_->setProgram("aisio"); // 確認 PATH 裡找得到，或改成絕對路徑
    proc_->setArguments({ apiName, "--json" });
    proc_->setProcessChannelMode(QProcess::SeparateChannels);

    // 設定 UTF-8 執行環境
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert("LANG", "C.UTF-8");
    env.insert("LC_ALL", "C.UTF-8");
    proc_->setProcessEnvironment(env);

    // 呼叫完成後更新 UI
    connect(proc_, &QProcess::finished, this, [this](int exitCode, QProcess::ExitStatus) {
        const QByteArray so = proc_->readAllStandardOutput();
        const QByteArray se = proc_->readAllStandardError();
        const QString out = QString::fromUtf8(so);
        const QString err = QString::fromUtf8(se);

        if (!err.isEmpty() && exitCode != 0) {
            QMessageBox::warning(this, tr("Ais.IO"), err);
        }
        ui->cipherText->setPlainText(out);

        proc_->deleteLater();
    });

    proc_->start();

    const QByteArray json = QJsonDocument(payload).toJson(QJsonDocument::Compact);
    proc_->write(json);
    proc_->closeWriteChannel();
}
