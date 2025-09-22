#include "base_encoder_window.h"
#include <ui_base_encoder_window.h>

BaseEncoderWindow::BaseEncoderWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::BaseEncoderWindow) {  // ← 初始化
    ui->setupUi(this);          // ← 建立 UI 元件
}

BaseEncoderWindow::~BaseEncoderWindow() {
    delete ui;   // 釋放記憶體
}

static QString humanSize(qint64 b) {
    const char* u[] = {"B","KB","MB","GB","TB","PB","EB","ZB","YB"};
    double s = double(b);
    int i = 0;
    while (s >= 1024.0 && i < 4) { s /= 1024.0; ++i; }
    return QString::number(s, 'f', (i==0 ? 0 : 2)) + " " + u[i];
}

static constexpr qint64 PREVIEW_LIMIT = 2LL * 1024 * 1024; // 2 MB

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

    const size_t need = f.len(static_cast<size_t>(in.size()), /*isEncode=*/true) + 8;
    QByteArray out;
    out.resize(int(need));
    const int n = f.enc(reinterpret_cast<const unsigned char*>(in.constData()),
                        size_t(in.size()),
                        out.data(),
                        size_t(out.size()));
    if (n < 0) {
        processErrorCode(n);
        return;
    }
    out.resize(n);
    ui->baseCipherText->setPlainText(QString::fromLatin1(out));

    // 寫入檔案 (如果有路徑的話)
    if (!ui->cipherTextOutputLineEdit->text().isEmpty()) {
        QString path = ui->cipherTextOutputLineEdit->text().trimmed();
        QFileInfo info(path);
        if (!info.absolutePath().isEmpty())
            QDir().mkpath(info.absolutePath());

        QSaveFile f(path);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            qWarning() << "Open failed:" << f.errorString();
            return;
        }

        qint64 n = f.write(out);
        if (n < 0) {
            qWarning() << "Write failed:" << f.errorString();
            return;
        }
        if (n != out.size()) {
            qWarning() << "Partial write:" << n << "of" << out.size();
            return;
        }
        if (!f.commit()) {
            qWarning() << "Commit failed:" << f.errorString();
            return;
        }
    }
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

    const size_t need = f.len(size_t(in.size()), /*isEncode=*/false) + 8;
    QByteArray out;
    out.resize(int(need));
    const int n = f.dec(in.constData(), size_t(in.size()),
                        reinterpret_cast<unsigned char*>(out.data()),
                        size_t(out.size()));
    if (n < 0) {
        processErrorCode(n);
        return;
    }
    out.resize(n);

    QString text = QString::fromUtf8(out.constData(), out.size());
    if (text.isEmpty() && !out.isEmpty()) {
        QString hex; hex.reserve(out.size() * 2);
        static const char* kHex = "0123456789ABCDEF";
        for (unsigned char c : out) { hex.append(kHex[c >> 4]); hex.append(kHex[c & 0xF]); }
        text = hex;
    }
    ui->basePlainText->setPlainText(text);

    // 寫入檔案 (如果有路徑的話)
    if (!ui->plainTextOutputLineEdit->text().isEmpty()) {
        QString path = ui->plainTextOutputLineEdit->text().trimmed();
        QFileInfo info(path);
        if (!info.absolutePath().isEmpty())
            QDir().mkpath(info.absolutePath());

        QSaveFile f(path);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            qWarning() << "Open failed:" << f.errorString();
            return;
        }

        qint64 n = f.write(out);
        if (n < 0) {
            qWarning() << "Write failed:" << f.errorString();
            return;
        }
        if (n != out.size()) {
            qWarning() << "Partial write:" << n << "of" << out.size();
            return;
        }
        if (!f.commit()) {
            qWarning() << "Commit failed:" << f.errorString();
            return;
        }
    }
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
