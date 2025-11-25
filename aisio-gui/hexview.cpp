#include "hexview.h"
#include "richtextdelegate.h"
#include <QHeaderView>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QRegularExpression>

HexView::HexView(QWidget *parent)
    : QWidget(parent) {
    table = new QTableWidget(this);
    auto layout = new QVBoxLayout(this);
    layout->setContentsMargins(0,0,0,0);
    layout->addWidget(table);

    setupTable();

    table->setItemDelegate(new RichTextDelegate(this));

    connect(table, &QTableWidget::cellClicked,
            this, &HexView::onCellClicked);

    connect(table, &QTableWidget::cellChanged,
            this, &HexView::onCellEdited);
}

void HexView::setupTable() {
    table->setColumnCount(18);

    QStringList headers;
    headers << "Addr";
    for (int i = 0; i < 16; ++i)
        headers << QString("%1").arg(i, 2, 16, QLatin1Char('0')).toUpper();
    headers << "ASCII";

    table->setHorizontalHeaderLabels(headers);

    table->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    table->verticalHeader()->setVisible(false);

    table->setColumnWidth(0, 90);
    for (int i = 1; i <= 16; ++i)
        table->setColumnWidth(i, 26);
    table->setColumnWidth(17, 140);
}

void HexView::setEditable(bool enabled) {
    editable = enabled;

    if (table->rowCount() == 0)
        return;

    table->setEditTriggers(enabled
                               ? QAbstractItemView::AllEditTriggers
                               : QAbstractItemView::NoEditTriggers);
}

void HexView::loadData(const QByteArray& data, QFontDatabase::SystemFont setFont) {
    buffer = data;

    const int bytesPerRow = 16;
    const int rowCount = (data.size() + bytesPerRow - 1) / bytesPerRow;

    table->clear();
    table->setRowCount(rowCount);
    table->setColumnCount(18);

    QFont font = QFontDatabase::systemFont(setFont);
    font.setPointSize(12);
    table->setFont(font);

    QStringList headers;
    headers << "Address";
    for (int i = 0; i < 16; ++i)
        headers << QString("%1").arg(i, 2, 16, QLatin1Char('0')).toUpper();
    headers << "ASCII";
    table->setHorizontalHeaderLabels(headers);

    table->setColumnWidth(0, 90);
    for (int i = 1; i <= 16; ++i)
        table->setColumnWidth(i, 32);
    table->setColumnWidth(17, 140);

    for (int row = 0; row < rowCount; ++row) {
        int offset = row * bytesPerRow;

        // 地址
        QString addr = QString("%1").arg(offset, 8, 16, QLatin1Char('0')).toUpper();
        table->setItem(row, 0, new QTableWidgetItem(addr));

        QString ascii;

        for (int i = 0; i < bytesPerRow; ++i) {
            int index = offset + i;
            QTableWidgetItem *item;

            if (index < buffer.size()) {
                unsigned char c = (unsigned char)buffer[index];
                QString hx = QString("%1").arg(c, 2, 16, QLatin1Char('0')).toUpper();
                item = new QTableWidgetItem(hx);
                ascii += (c >= 32 && c < 127) ? QChar(c) : '.';
            } else {
                item = new QTableWidgetItem("");  // ← 必須建立空格項目
                ascii += ' ';
            }

            item->setTextAlignment(Qt::AlignCenter);
            table->setItem(row, 1 + i, item);
        }

        table->setItem(row, 17, new QTableWidgetItem(ascii));
    }

    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    table->verticalHeader()->setVisible(false);
    table->setEditTriggers(editable
                               ? QAbstractItemView::AllEditTriggers
                               : QAbstractItemView::NoEditTriggers);
}

void HexView::gotoOffset(qint64 offset) {
    int row = offset / 16;
    int col = (offset % 16) + 1;

    table->scrollToItem(table->item(row, col), QAbstractItemView::PositionAtCenter);
    highlightOffset(offset);
}

qint64 HexView::findHex(const QByteArray &hexBytes, qint64 start) {
    int idx = buffer.indexOf(hexBytes, start);
    if (idx >= 0) gotoOffset(idx);
    return idx;
}

qint64 HexView::findText(const QString &text, qint64 start) {
    QByteArray bytes = text.toUtf8();
    int idx = buffer.indexOf(bytes, start);
    if (idx >= 0) gotoOffset(idx);
    return idx;
}

void HexView::highlightOffset(qint64 offset) {
    int row = offset / 16;
    int col = (offset % 16) + 1;

    // === 清除 HEX 區 highlight ===
    for (int r = 0; r < table->rowCount(); ++r)
        for (int c = 1; c <= 16; ++c) {
            auto cell = table->item(r, c);
            if (cell)
                cell->setBackground(Qt::transparent);
        }

    // === HEX 高亮 ===
    if (auto target = table->item(row, col))
        target->setBackground(Qt::red);

    // === ASCII 高亮 ===
    QTableWidgetItem *asciiItem = table->item(row, 17);
    if (!asciiItem) {
        asciiItem = new QTableWidgetItem;
        table->setItem(row, 17, asciiItem);
    }

    QString html;
    html.reserve(0x200);

    for (int i = 0; i < 16; ++i) {
        int idx = row * 16 + i;
        QChar ch;

        if (idx < buffer.size()) {
            unsigned char c = buffer[idx];
            ch = (c >= 32 && c < 127) ? QChar(c) : QChar('.');
        } else {
            ch = ' ';
        }

        // 高亮目標字
        if (i == (offset % 16)) {
            html += QString("<span style=\"background-color:red\">%1</span>").arg(ch);
        } else {
            html += ch;
        }
    }

    asciiItem->setData(Qt::DisplayRole, html);
}

void HexView::onCellClicked(int row, int col) {
    if (col == 0) return;
    if (col == 17) return;

    int offset = row * 16 + (col - 1);
    highlightOffset(offset);

    emit offsetSelected(offset);
}

void HexView::onCellEdited(int row, int col) {
    if (!editable) return;

    // Address 欄、ASCII 欄不編輯
    if (col == 0 || col == 17) return;

    QTableWidgetItem *item = table->item(row, col);
    if (!item) return;

    QString text = item->text();

    // Regex：必須是 2 位 HEX
    static QRegularExpression hex2("^[0-9A-Fa-f]{2}$");
    if (text.size() != 2 || !hex2.match(text).hasMatch()) {
        // 還原原本 HEX
        int idx = row * 16 + (col - 1);
        unsigned char origin = buffer[idx];
        item->setText(QString("%1").arg(origin, 2, 16, QLatin1Char('0')).toUpper());
        return;
    }

    // 寫入 buffer
    int idx = row * 16 + (col - 1);
    if (idx >= buffer.size()) {
        item->setText("  "); // 或者 ""
        return;
    }
    else
    buffer[idx] = (char)text.toUInt(nullptr, 16);

    // 重建 ASCII 一整列（不讀 table->item(row,17)->text()！）
    QString ascii_html;
    ascii_html.reserve(512);

    for (int i = 0; i < 16; ++i)
    {
        int bi = row * 16 + i;
        QChar ch;

        if (bi < buffer.size()) {
            unsigned char c = buffer[bi];
            ch = (c >= 32 && c < 127) ? QChar(c) : QChar('.');
        } else {
            ch = ' ';
        }

        ascii_html += ch;
    }

    // 完整更新 ASCII 欄位（DisplayRole -> RichTextDelegate）
    QTableWidgetItem *asciiItem = table->item(row, 17);
    if (!asciiItem) {
        asciiItem = new QTableWidgetItem;
        table->setItem(row, 17, asciiItem);
    }
    asciiItem->setData(Qt::DisplayRole, ascii_html);

    // ※ 可選：更新 highlight（若你想保留選中狀態）
    highlightOffset(idx);
}
