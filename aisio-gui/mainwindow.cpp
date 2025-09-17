#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow) {  // ← 初始化
    ui->setupUi(this);          // ← 建立 UI 元件
}

MainWindow::~MainWindow() {
    delete ui;   // 釋放記憶體
}

// ---- 把 ComboBox 文字映射到對應 API ----
MainWindow::BaseFns MainWindow::selectBaseFns(const QString& mode) const {
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

void MainWindow::on_encodeButton_clicked() {
    // 文字 → UTF-8 bytes
    const QByteArray in = ui->plainText->toPlainText().toUtf8();
    const QString mode = ui->modeComboBox->currentText();
    const MainWindow::BaseFns f = selectBaseFns(mode);
    if (!f.len || !f.enc) {
        QMessageBox::warning(this, tr("Wrong"), tr("Unsupported Base mode: %1").arg(mode));
        return;
    }

    // 預估輸出長度（庫有提供 Length 函式）:contentReference[oaicite:2]{index=2}
    const size_t need = f.len(static_cast<size_t>(in.size()), /*isEncode=*/true) + 8; // 多抓一點餘裕
    QByteArray out;
    out.resize(int(need));
    const int n = f.enc(reinterpret_cast<const unsigned char*>(in.constData()),
                        size_t(in.size()),
                        out.data(),
                        size_t(out.size()));
    if (n < 0) {
        QMessageBox::warning(this, tr("Encoding failed"), tr("Error code: %1").arg(n));
        return;
    }
    out.resize(n);
    ui->cipherText->setPlainText(QString::fromLatin1(out)); // BaseN 字串 → 直接以 Latin1 顯示
}

void MainWindow::on_decodeButton_clicked() {
    // 文字 → UTF-8 bytes
    const QByteArray in = ui->cipherText->toPlainText().toLatin1();
    const QString mode = ui->modeComboBox->currentText();
    const auto f = selectBaseFns(mode);
    if (!f.len || !f.dec) {
        QMessageBox::warning(this, tr("Wrong"), tr("Unsupported Base mode: %1").arg(mode));
        return;
    }

    const size_t need = f.len(size_t(in.size()), /*isEncode=*/false) + 8; // 預估原始 bytes 長度  :contentReference[oaicite:3]{index=3}
    QByteArray out;
    out.resize(int(need));
    const int n = f.dec(in.constData(), size_t(in.size()),
                        reinterpret_cast<unsigned char*>(out.data()),
                        size_t(out.size()));
    if (n < 0) {
        QMessageBox::warning(this, tr("Decoding failed"), tr("Error code: %1").arg(n));
        return;
    }
    out.resize(n);

    // 嘗試用 UTF-8 顯示原始位元組；若失敗就退而求其次用十六進位
    QString text = QString::fromUtf8(out.constData(), out.size());
    if (text.isEmpty() && !out.isEmpty()) {
        QString hex; hex.reserve(out.size() * 2);
        static const char* kHex = "0123456789ABCDEF";
        for (unsigned char c : out) { hex.append(kHex[c >> 4]); hex.append(kHex[c & 0xF]); }
        text = hex;
    }
    ui->plainText->setPlainText(text);
}
