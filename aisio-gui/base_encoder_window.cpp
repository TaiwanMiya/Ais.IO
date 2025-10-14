#include "base_encoder_window.h"
#include "chunked_appender.h"
#include "config.h"
#include <ui_base_encoder_window.h>
#include <QtConcurrent>
#include <QFutureWatcher>
#include <QFuture>

BaseEncoderWindow::BaseEncoderWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::BaseEncoderWindow) {  // ← 初始化
    ui->setupUi(this);          // ← 建立 UI 元件
}

BaseEncoderWindow::~BaseEncoderWindow() {
    delete ui;   // 釋放記憶體
}

// static constexpr qint64 PREVIEW_LIMIT = 2LL * 1024 * 1024; // 2 MB
// static constexpr qint64 PREVIEW_LIMIT = 2LL * 1024; // 2 KB
const qint64 PREVIEW_LIMIT = Config::instance().previewLimitBytes();
const qint64 CHUNK_SIZE    = Config::instance().chunkAppendSize();

static QString humanSize(qint64 b) {
    const char* u[] = {"B","KB","MB","GB","TB","PB","EB","ZB","YB"};
    double s = double(b);
    int i = 0;
    while (s >= 1024.0 && i < 8) { s /= 1024.0; ++i; }
    return QString::number(s, 'f', (i==0 ? 0 : 2)) + " " + u[i];
}

// ---- 把 ComboBox 文字映射到對應 API ----
BaseEncoderWindow::BaseFns BaseEncoderWindow::selectBaseFns(const QString& mode) const {
    using FLen = size_t(*)(size_t, bool);
    using FEnc = int(*)(const unsigned char*, size_t, char*, size_t);
    using FDec = int(*)(const char*, size_t, unsigned char*, size_t);

    struct Row { const char* name; FLen L; FEnc E; FDec D; };
    static const Row table[] = {
        {"Base10", Base10Length, Base10Encode, Base10Decode},
        {"Base16", Base16Length, Base16Encode, Base16Decode},
        {"Base32", Base32Length, Base32Encode, Base32Decode},
        {"Base58", Base58Length, Base58Encode, Base58Decode},
        {"Base62", Base62Length, Base62Encode, Base62Decode},
        {"Base64", Base64Length, Base64Encode, Base64Decode},
        {"Base85", Base85Length, Base85Encode, Base85Decode},
        {"Base91", Base91Length, Base91Encode, Base91Decode},
    };
    for (const Row &r : table)
        if (mode.compare(QLatin1String(r.name), Qt::CaseInsensitive) == 0)
            return {r.L, r.E, r.D};
    return {};
}

void BaseEncoderWindow::processErrorCode(const int& n) {
    QString msg;
    switch (n){
    case -1:
        msg = tr("Error code: %1\nThe input or output pointer is null.").arg(n);
        break;
    case -2:
        msg = tr("Error code: %1\nThe output buffer is insufficient.").arg(n);
        break;
    case -3:
        msg = tr("Error code: %1\nThe input length is invalid; it must be a specific length when decoding.").arg(n);
        break;
    case -4:
        msg = tr("Error code: %1\nAn illegal character appears during decoding. (Not a valid character.)").arg(n);
        break;
    default:
        msg = tr("Error code: %1\nUnknown error.").arg(n);
        break;
    }
    QMessageBox::warning(this, tr("Wrong"), msg);
}

void BaseEncoderWindow::on_baseEncodeButton_clicked() {
    const QString mode = ui->baseModeComboBox->currentText();
    const BaseFns f = selectBaseFns(mode);
    if (!f.len || !f.enc) {
        QMessageBox::warning(this, tr("Wrong"), tr("Unsupported Base mode: %1").arg(mode));
        return;
    }

    QByteArray in = m_plainFromFile ? m_plainBuffer
                                    : ui->basePlainText->toPlainText().toUtf8();

    if (in.isEmpty()) {
        QMessageBox::warning(this, tr("Wrong"), tr("Please enter plain text first."));
        return;
    }

    // 進度對話框：>1秒才顯示
    auto* dlg = new QProgressDialog(tr("Encoding…"), tr("Cancel"), 0, 0, this);
    dlg->setWindowModality(Qt::ApplicationModal);
    dlg->setMinimumDuration(1000);
    dlg->setAutoClose(true);

    // 回傳 (data, err)；err==0 表成功，否則為錯誤碼
    using EncodeResult = QPair<QByteArray,int>;

    auto* watcher = new QFutureWatcher<EncodeResult>(this);
    QObject::connect(dlg, &QProgressDialog::canceled, watcher, &QFutureWatcher<EncodeResult>::cancel);

    // 背景執行：一次性 API，這裡不做 chunk 進度；日後要更細可改成分段回報
    QFuture<EncodeResult> fut = QtConcurrent::run([in, f]() -> EncodeResult {
        QByteArray out; out.resize(int(f.len(size_t(in.size()), /*encode*/true) + 8));
        const int n = f.enc(reinterpret_cast<const unsigned char*>(in.constData()),
                            size_t(in.size()),
                            out.data(),
                            size_t(out.size()));
        if (n < 0) return qMakePair(QByteArray(), n);
        out.resize(n);
        return qMakePair(out, 0);
    });
    watcher->setFuture(fut);

    // 完成：回主執行緒更新 UI + 寫檔
    QObject::connect(watcher, &QFutureWatcher<EncodeResult>::finished, this, [=] {
        dlg->close(); dlg->deleteLater();

        const EncodeResult res = watcher->result();
        watcher->deleteLater();

        if (res.second != 0) {
            processErrorCode(res.second);
            return;
        }

        const QByteArray out = res.first;

        m_cipherBuffer = out;
        m_cipherPath.clear();
        m_cipherFromFile = true;

        const QByteArray preview = (out.size() > PREVIEW_LIMIT)
                                       ? out.left(PREVIEW_LIMIT) : out;

        ui->baseCipherText->blockSignals(true);
        auto app = new ChunkedAppender(ui->baseCipherText, preview, 128*1024, this);
        connect(app, &ChunkedAppender::finished, this, [=] {
            ui->baseCipherText->blockSignals(false);
            m_cipherFromFile = true;
        });
        app->start();

        if (ui->decodeSizeLabel) ui->decodeSizeLabel->setText(humanSize(out.size()));
        if (out.size() > PREVIEW_LIMIT) {
            statusBar()->showMessage(
                tr("Show only the front: %1, Total size: %2")
                    .arg(humanSize(PREVIEW_LIMIT), humanSize(out.size())));
        } else {
            statusBar()->clearMessage();
        }

        // 輸出路徑
        const QString path = ui->cipherTextOutputLineEdit->text().trimmed();
        if (!path.isEmpty()) {
            QFileInfo info(path);
            if (!info.absolutePath().isEmpty())
                QDir().mkpath(info.absolutePath());

            QSaveFile f(path);
            if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                QMessageBox::warning(this, tr("Error"), f.errorString());
                return;
            }
            if (f.write(out) != out.size() || !f.commit()) {
                QMessageBox::warning(this, tr("Error"), tr("Write failed: %1").arg(f.errorString()));
            }
        }
    });

    dlg->show();
}

void BaseEncoderWindow::on_baseDecodeButton_clicked() {
    const QString mode = ui->baseModeComboBox->currentText();
    const auto f = selectBaseFns(mode);
    if (!f.len || !f.dec) {
        QMessageBox::warning(this, tr("Wrong"), tr("Unsupported Base mode: %1").arg(mode));
        return;
    }

    QByteArray in = m_cipherFromFile ? m_cipherBuffer
                                     : ui->baseCipherText->toPlainText().toLatin1();

    if (in.isEmpty()) {
        QMessageBox::warning(this, tr("Wrong"), tr("Please enter cipher text first."));
        return;
    }

    auto* dlg = new QProgressDialog(tr("Decoding…"), tr("Cancel"), 0, 0, this);
    dlg->setWindowModality(Qt::ApplicationModal);
    dlg->setMinimumDuration(1000);
    dlg->setAutoClose(true);

    using DecodeResult = QPair<QByteArray,int>;

    auto* watcher = new QFutureWatcher<DecodeResult>(this);
    QObject::connect(dlg, &QProgressDialog::canceled, watcher, &QFutureWatcher<DecodeResult>::cancel);

    QFuture<DecodeResult> fut = QtConcurrent::run([in, f]() -> DecodeResult {
        QByteArray out; out.resize(int(f.len(size_t(in.size()), /*encode*/false) + 8));
        const int n = f.dec(in.constData(), size_t(in.size()),
                            reinterpret_cast<unsigned char*>(out.data()),
                            size_t(out.size()));
        if (n < 0) return qMakePair(QByteArray(), n);
        out.resize(n);
        return qMakePair(out, 0);
    });
    watcher->setFuture(fut);

    // 完成：回主執行緒更新 UI + 寫檔
    QObject::connect(watcher, &QFutureWatcher<DecodeResult>::finished, this, [=] {
        dlg->close(); dlg->deleteLater();

        const DecodeResult res = watcher->result();
        watcher->deleteLater();

        if (res.second != 0) {
            processErrorCode(res.second);
            return;
        }

        const QByteArray out = res.first;

        m_plainBuffer = out;
        m_plainPath.clear();
        m_plainFromFile = true;

        QByteArray displayBytes;
        QString text = QString::fromUtf8(out.constData(), out.size());
        if (!text.isEmpty() || out.isEmpty()) {
            // UTF-8 OK：直接用原 bytes 走 Latin1（多數 Base 輸出是 ASCII，可顯示）
            displayBytes = out;
        } else {
            // 回退 Hex（還是 bytes，比先拼 QString 再拆更省）
            static const char H[] = "0123456789ABCDEF";
            displayBytes.resize(out.size()*2);
            for (int i=0;i<out.size();++i) {
                const unsigned char c = static_cast<unsigned char>(out[i]);
                displayBytes[2*i]   = H[c>>4];
                displayBytes[2*i+1] = H[c&0xF];
            }
        }

        const QByteArray preview = (displayBytes.size() > PREVIEW_LIMIT)
                                       ? displayBytes.left(PREVIEW_LIMIT) : displayBytes;

        ui->basePlainText->blockSignals(true);
        // 分段灌入到左側
        auto app = new ChunkedAppender(ui->basePlainText, preview, 128*1024, this);
        connect(app, &ChunkedAppender::finished, this, [=] {
            ui->basePlainText->blockSignals(false);
            m_plainFromFile = true;
        });
        app->start();

        if (ui->encodeSizeLabel) ui->encodeSizeLabel->setText(humanSize(out.size()));
        if (displayBytes.size() > PREVIEW_LIMIT) {
            statusBar()->showMessage(
                tr("Show only the front: %1, Total size: %2")
                    .arg(humanSize(PREVIEW_LIMIT), humanSize(displayBytes.size())));
        } else {
            statusBar()->clearMessage();
        }

        // 輸出路徑
        const QString path = ui->plainTextOutputLineEdit->text().trimmed();
        if (!path.isEmpty()) {
            QFileInfo info(path);
            if (!info.absolutePath().isEmpty())
                QDir().mkpath(info.absolutePath());

            QSaveFile f(path);
            if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                QMessageBox::warning(this, tr("Error"), f.errorString());
                return;
            }
            if (f.write(out) != out.size() || !f.commit()) {
                QMessageBox::warning(this, tr("Error"), tr("Write failed: %1").arg(f.errorString()));
            }
        }
    });

    dlg->show();
}

void BaseEncoderWindow::on_encodeToolButton_clicked() {
    QString path = QFileDialog::getOpenFileName(this);
    if (path.isEmpty())
        return;

    ui->encodePathLineEdit->setText(path);

    QFileInfo fi(path);
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, tr("Error"), tr("Unable to open file: %1").arg(path));
        return;
    }

    m_plainBuffer    = f.readAll();
    m_plainPath      = path;
    m_plainFromFile  = true;

    const QByteArray preview = (fi.size() > PREVIEW_LIMIT)
                                   ? m_plainBuffer.left(PREVIEW_LIMIT)
                                   : m_plainBuffer;

    QSignalBlocker block(*ui->basePlainText);
    ui->basePlainText->setPlainText(QString::fromUtf8(preview));

    if (ui->encodeSizeLabel) ui->encodeSizeLabel->setText(humanSize(fi.size()));
    if (fi.size() > PREVIEW_LIMIT) {
        statusBar()->showMessage(
            tr("Show only the front: %1, Total size: %2")
                .arg(humanSize(PREVIEW_LIMIT), humanSize(fi.size())));
    } else {
        statusBar()->clearMessage();
    }
}

void BaseEncoderWindow::on_decodeToolButton_clicked() {
    const QString path = QFileDialog::getOpenFileName(this);
    if (path.isEmpty()) return;

    ui->decodePathLineEdit->setText(path);

    QFileInfo fi(path);
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, tr("Error"), tr("Unable to open file: %1").arg(path));
        return;
    }

    m_cipherBuffer    = f.readAll();
    m_cipherPath      = path;
    m_cipherFromFile  = true;

    const QByteArray preview = (fi.size() > PREVIEW_LIMIT)
                                   ? m_cipherBuffer.left(PREVIEW_LIMIT)
                                   : m_cipherBuffer;

    QSignalBlocker block(*ui->baseCipherText);
    ui->baseCipherText->setPlainText(QString::fromUtf8(preview));

    if (ui->decodeSizeLabel) ui->decodeSizeLabel->setText(humanSize(fi.size()));
    if (fi.size() > PREVIEW_LIMIT) {
        statusBar()->showMessage(
            tr("Show only the front: %1, Total size: %2")
                .arg(humanSize(PREVIEW_LIMIT), humanSize(fi.size())));
    } else {
        statusBar()->clearMessage();
    }
}

void BaseEncoderWindow::on_basePlainText_textChanged() {
    m_plainFromFile = false;
    m_plainBuffer.clear();

    if (ui->encodeSizeLabel)
        ui->encodeSizeLabel->setText(humanSize(ui->basePlainText->toPlainText().toUtf8().size()));
}

void BaseEncoderWindow::on_baseCipherText_textChanged() {
    m_cipherFromFile = false;
    m_cipherBuffer.clear();

    if (ui->decodeSizeLabel)
        ui->decodeSizeLabel->setText(humanSize(ui->baseCipherText->toPlainText().toUtf8().size()));
}

void BaseEncoderWindow::on_plainTextOutputToolButton_clicked() {
    QString path = QFileDialog::getSaveFileName(this);
    if (path.isEmpty())
        return;

    ui->plainTextOutputLineEdit->setText(path);
}

void BaseEncoderWindow::on_cipherTextOutputToolButton_clicked() {
    QString path = QFileDialog::getSaveFileName(this);
    if (path.isEmpty())
        return;

    ui->cipherTextOutputLineEdit->setText(path);
}
