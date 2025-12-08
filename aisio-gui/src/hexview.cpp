#include "../include/hexview.h"

#include <QPainter>
#include <QScrollBar>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QFontDatabase>

HexView::HexView(QWidget *parent)
    : QAbstractScrollArea(parent) {
    // 用等寬字體，Hex 才會漂亮
    QFont f = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    setFont(f);

    setFocusPolicy(Qt::StrongFocus);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    updateMetrics();

    setAttribute(Qt::WA_OpaquePaintEvent);
    setAttribute(Qt::WA_NoSystemBackground);

    for (int i = 0; i < 256; i++) {
        m_hexCache[i] = QString("%1").arg(i, 2, 16, QLatin1Char('0')).toUpper();
        m_asciiCache[i] = (i >= 0x20 && i < 0x7F) ? QChar(i) : QChar('.');
    }
}

void HexView::updateMetrics() {
    QFontMetrics fm(font());
    m_charWidth  = fm.horizontalAdvance(QLatin1Char('0'));
    m_lineHeight = fm.height();

    m_hexCellWidth = m_charWidth * 3;

    int addrWidth = 8 * m_charWidth;
    m_hexStartX = m_leftMargin + addrWidth + m_charWidth * 2;
    m_asciiStartX = m_hexStartX + m_bytesPerLine * m_hexCellWidth + m_charWidth * 2;

    updateScrollBars();
}

void HexView::updateScrollBars() {
    int totalLines = (m_data.size() + m_bytesPerLine - 1) / m_bytesPerLine;
    if (totalLines < 0) totalLines = 0;

    int linesPerPage = std::max(1, (viewport()->height() - m_topMargin * 2) / m_lineHeight);

    QScrollBar *v = verticalScrollBar();
    v->setRange(0, std::max(0, totalLines - linesPerPage));
    v->setSingleStep(1);
    v->setPageStep(linesPerPage);
}

void HexView::loadData(const QByteArray &data) {
    m_data = data;
    if (m_cursorOffset >= m_data.size())
        m_cursorOffset = m_data.size() - 1;

    verticalScrollBar()->setValue(0);
    updateScrollBars();
    viewport()->update();
}

void HexView::setEditable(bool editable) {
    m_editable = editable;
}

void HexView::paintEvent(QPaintEvent *event) {
    Q_UNUSED(event);

    QPainter p(viewport());
    QRect vpRect = viewport()->rect();
    p.fillRect(vpRect, QColor(0x1e, 0x1e, 0x1e));

    if (m_data.isEmpty())
        return;

    int vpos = verticalScrollBar()->value();

    int linesPerPage = std::max(1, (viewport()->height() - m_topMargin*2) / m_lineHeight);
    int lastLine = vpos + linesPerPage;

    int byteCount = m_data.size();
    int totalLines = (byteCount + m_bytesPerLine - 1) / m_bytesPerLine;
    if (lastLine > totalLines)
        lastLine = totalLines;

    for (int line = vpos; line < lastLine; ++line)
    {
        int y = m_topMargin + (line - vpos + 1) * m_lineHeight;
        qint64 base = qint64(line) * m_bytesPerLine;

        // 地址欄
        QString addr = QString("%1").arg(base, 8, 16, QLatin1Char('0')).toUpper();
        p.setPen(QColor(160,160,160));
        p.drawText(m_leftMargin, y, addr);

        for (int col = 0; col < m_bytesPerLine; col++)
        {
            qint64 off = base + col;
            if (off >= byteCount) break;

            unsigned char byte = (unsigned char)m_data.at(off);

            int hx = m_hexStartX + col * m_hexCellWidth;
            int ax = m_asciiStartX + col * m_charWidth;
            QRect hexRect(hx, y - m_lineHeight + 2, m_hexCellWidth, m_lineHeight);
            QRect asciiRect(ax, y - m_lineHeight + 2, m_charWidth, m_lineHeight);

            bool isCursor = (off == m_cursorOffset);

            if (isCursor) {
                p.fillRect(hexRect, QColor(70, 100, 160));
                p.fillRect(asciiRect, QColor(70, 100, 160));
                p.setPen(Qt::white);
            } else {
                p.setPen(QColor(230,230,230));
            }

            p.drawText(hexRect, Qt::AlignLeft | Qt::AlignVCenter, m_hexCache[byte]);
            p.drawText(asciiRect, Qt::AlignLeft | Qt::AlignVCenter, m_asciiCache[byte]);
        }
    }
}

void HexView::resizeEvent(QResizeEvent *event) {
    QAbstractScrollArea::resizeEvent(event);
    updateMetrics();
    updateScrollBars();
    viewport()->update();
}

void HexView::wheelEvent(QWheelEvent *event) {
    int delta = event->angleDelta().y();
    if (delta == 0)
        return;

    int lines = delta / 120; // 120 是一格滾輪
    int newVal = verticalScrollBar()->value() - lines;
    // newVal = qBound(0, newVal, verticalScrollBar()->maximum());
    verticalScrollBar()->setValue(newVal);
    event->accept();

    QAbstractScrollArea::wheelEvent(event);
}

QSize HexView::sizeHint() const {
    // 大概顯示個 16 行，寬度根據 HEX + ASCII 算一下
    int w = m_asciiStartX + m_bytesPerLine * m_charWidth + m_leftMargin;
    int h = m_topMargin * 2 + m_lineHeight * 16;
    return QSize(w, h);
}

QSize HexView::minimumSizeHint() const {
    return QSize(200, 100);
}

void HexView::ensureVisible(qint64 offset) {
    if (offset < 0 || m_data.isEmpty())
        return;

    int line = int(offset / m_bytesPerLine);
    QScrollBar *v = verticalScrollBar();

    int firstLine = v->value();
    int linesPerPage = v->pageStep();
    int lastLine = firstLine + linesPerPage - 1;

    if (line < firstLine)
        v->setValue(line);
    else if (line > lastLine)
        v->setValue(line - linesPerPage + 1);
}

void HexView::moveCursorRelative(qint64 deltaBytes) {
    if (m_data.isEmpty())
        return;

    qint64 newOff = m_cursorOffset + deltaBytes;
    if (newOff < 0) newOff = 0;
    if (newOff >= m_data.size()) newOff = m_data.size() - 1;

    m_cursorOffset = newOff;
    ensureVisible(m_cursorOffset);
    viewport()->update();
}

void HexView::moveCursorLineRelative(qint64 deltaLines) {
    moveCursorRelative(deltaLines * m_bytesPerLine);
}

void HexView::moveCursorToLineStart() {
    if (m_data.isEmpty())
        return;

    qint64 line = m_cursorOffset / m_bytesPerLine;
    qint64 newOff = line * m_bytesPerLine;
    if (newOff >= m_data.size())
        newOff = m_data.size() - 1;

    m_cursorOffset = newOff;
    ensureVisible(m_cursorOffset);
    viewport()->update();
}

void HexView::moveCursorToLineEnd() {
    if (m_data.isEmpty())
        return;

    qint64 line = m_cursorOffset / m_bytesPerLine;
    qint64 newOff = line * m_bytesPerLine + (m_bytesPerLine - 1);
    if (newOff >= m_data.size())
        newOff = m_data.size() - 1;

    m_cursorOffset = newOff;
    ensureVisible(m_cursorOffset);
    viewport()->update();
}

void HexView::handleHexEdit(QKeyEvent *event) {
    if (!m_editable || m_data.isEmpty())
        return;

    int key = event->key();
    QChar c = event->text().isEmpty() ? QChar() : event->text().at(0);

    auto hexVal = [](QChar ch) -> int {
        if (ch >= '0' && ch <= '9') return ch.unicode() - '0';
        if (ch >= 'a' && ch <= 'f') return ch.unicode() - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch.unicode() - 'A' + 10;
        return -1;
    };

    int v = hexVal(c);
    if (v < 0)
        return;

    // 簡易版：每次輸入一個 hex 字元，覆寫高／低位 nibble
    static bool highNibble = true;

    unsigned char oldByte = static_cast<unsigned char>(m_data.at(m_cursorOffset));
    unsigned char newByte;

    if (highNibble) {
        newByte = (unsigned char)((v << 4) | (oldByte & 0x0F));
    } else {
        newByte = (unsigned char)((oldByte & 0xF0) | v);
    }

    m_data[m_cursorOffset] = char(newByte);
    highNibble = !highNibble;

    if (!highNibble) {
        // 還在同一 byte 的低位，不移動游標
    } else {
        // 高位寫完 → 游標移到下一個 byte
        moveCursorRelative(1);
    }

    viewport()->update();
}

void HexView::keyPressEvent(QKeyEvent *event) {
    if (event->modifiers() & (Qt::ControlModifier | Qt::AltModifier | Qt::MetaModifier)) {
        // Ctrl+F 等交給外面 (HexForm 的 shortcut)，這裡不處理
        QAbstractScrollArea::keyPressEvent(event);
        return;
    }

    switch (event->key()) {
    case Qt::Key_Left:
        moveCursorRelative(-1);
        return;
    case Qt::Key_Right:
        moveCursorRelative(1);
        return;
    case Qt::Key_Up:
        moveCursorLineRelative(-1);
        return;
    case Qt::Key_Down:
        moveCursorLineRelative(1);
        return;
    case Qt::Key_PageUp:
        moveCursorLineRelative(-verticalScrollBar()->pageStep());
        return;
    case Qt::Key_PageDown:
        moveCursorLineRelative(verticalScrollBar()->pageStep());
        return;
    case Qt::Key_Home:
        moveCursorToLineStart();
        return;
    case Qt::Key_End:
        moveCursorToLineEnd();
        return;
    default:
        break;
    }

    // 其餘交給 hex 編輯
    handleHexEdit(event);
}

void HexView::mousePressEvent(QMouseEvent *event) {
    if (event->button() != Qt::LeftButton) return;

    int vpos = verticalScrollBar()->value();
    int y = event->pos().y() - m_topMargin;
    if (y < 0) return;

    int lineOffset = y / m_lineHeight;
    int line = vpos + lineOffset;

    qint64 base = qint64(line) * m_bytesPerLine;
    if (base >= m_data.size()) return;

    int x = event->pos().x();
    qint64 col = -1;

    if (x >= m_hexStartX && x < m_hexStartX + m_bytesPerLine * m_hexCellWidth)
        col = (x - m_hexStartX) / m_hexCellWidth;
    else if (x >= m_asciiStartX && x < m_asciiStartX + m_bytesPerLine * m_charWidth)
        col = (x - m_asciiStartX) / m_charWidth;
    else
        return;

    qint64 off = base + col;
    if (off >= m_data.size()) off = m_data.size() - 1;

    m_cursorOffset = off;
    viewport()->update();
}

qint64 HexView::findBytes(const QByteArray &pattern, qint64 start, bool backwards)
{
    if (pattern.isEmpty() || m_data.isEmpty())
        return -1;

    if (start < 0) start = 0;
    if (start >= m_data.size()) start = m_data.size() - 1;

    qint64 found = -1;

    if (!backwards) {
        int pos = m_data.indexOf(pattern, int(start));
        if (pos >= 0)
            found = pos;
    } else {
        // 從 0 ~ start 之間找最後一個
        int pos = m_data.indexOf(pattern);
        while (pos >= 0 && pos <= start) {
            found = pos;
            pos = m_data.indexOf(pattern, pos + 1);
        }
    }

    if (found >= 0) {
        m_cursorOffset = found;
        ensureVisible(m_cursorOffset);
        viewport()->update();
    }

    return found;
}

void HexView::gotoOffset(qint64 offset) {
    if (m_data.isEmpty())
        return;

    if (offset < 0) offset = 0;
    if (offset >= m_data.size()) offset = m_data.size() - 1;

    m_cursorOffset = offset;
    ensureVisible(m_cursorOffset);
    viewport()->update();
}

qint64 HexView::offsetFromIndex(const QModelIndex &idx) const {
    Q_UNUSED(idx);
    // 目前沒有真正的 model/index，直接回傳目前游標 offset
    return m_cursorOffset;
}

QModelIndex HexView::currentIndex() const {
    // 沒有 model，就回傳一個空的
    return QModelIndex();
}

qint64 HexView::currentOffset() const {
    return m_cursorOffset;
}
