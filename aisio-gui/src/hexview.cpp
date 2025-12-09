#include "../include/hexview.h"

#include <QPainter>
#include <QScrollBar>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QFontDatabase>
#include <QtMath>
#include <QDebug>

HexView::HexView(QWidget *parent)
    : QAbstractScrollArea(parent)
{
    // 用系統等寬字型
    QFont f = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    setFont(f);

    setFocusPolicy(Qt::StrongFocus);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    setAttribute(Qt::WA_OpaquePaintEvent);
    setAttribute(Qt::WA_NoSystemBackground);

    // HEX / ASCII 字元快取
    for (int i = 0; i < 256; ++i) {
        m_hexCache[i] = QString("%1").arg(i, 2, 16, QLatin1Char('0')).toUpper();
        m_asciiCache[i] = (i >= 0x20 && i < 0x7F) ? QChar(i) : QChar('.');
    }

    updateMetrics();
}

// 依視窗寬度 + 字體度量決定每行顯示多少 bytes
void HexView::recalcBytesPerLineForWidth(int viewportWidth)
{
    if (viewportWidth <= 0 || m_charWidth <= 0 || m_hexCellWidth <= 0)
        return;

    // 地址欄
    int addrWidth = addressChars() * m_charWidth;
    int gapAddrHex  = m_charWidth * 2; // 地址與 HEX 中間空隙
    int gapHexAscii = m_charWidth * 2; // HEX 與 ASCII 中間空隙
    int rightMargin = m_leftMargin;

    int hexStartBase = m_leftMargin + addrWidth + gapAddrHex;

    int fixed = hexStartBase + gapHexAscii + rightMargin;
    int usable = viewportWidth - fixed;
    if (usable <= 0) {
        m_bytesPerLine = 4;
    } else {
        int perByte = m_hexCellWidth + m_charWidth;
        int maxByWidth = usable / perByte;
        if (maxByWidth < 4)
            maxByWidth = 4;

        const int kMaxBytesPerLine = 32; // 避免一行太長導致太重
        if (maxByWidth > kMaxBytesPerLine)
            maxByWidth = kMaxBytesPerLine;

        m_bytesPerLine = maxByWidth;
    }

    // 根據新的 bytesPerLine，更新 HEX / ASCII 起始 X
    int addrWidth2 = addressChars() * m_charWidth;
    m_hexStartX   = m_leftMargin + addrWidth2 + gapAddrHex;
    m_asciiStartX = m_hexStartX + m_bytesPerLine * m_hexCellWidth + gapHexAscii;
}

// 更新度量
void HexView::updateMetrics()
{
    QFontMetrics fm(font());
    m_charWidth    = fm.horizontalAdvance(QLatin1Char('0'));
    m_lineHeight   = fm.height();
    m_hexCellWidth = m_charWidth * 3;

    recalcBytesPerLineForWidth(viewport()->width());
    ensureLineCacheCapacity();
    updateScrollBars();
}

// 根據資料大小與視窗高度更新捲軸
void HexView::updateScrollBars()
{
    int totalLines = 0;
    if (!m_data.isEmpty() && m_bytesPerLine > 0) {
        totalLines = (m_data.size() + m_bytesPerLine - 1) / m_bytesPerLine;
    }

    int linesPerPage = 1;
    if (m_lineHeight > 0) {
        linesPerPage = qMax(1, (viewport()->height() - m_topMargin * 2) / m_lineHeight);
    }

    QScrollBar *v = verticalScrollBar();
    v->setRange(0, qMax(0, totalLines - linesPerPage));
    v->setSingleStep(1);
    v->setPageStep(linesPerPage);
}

// 依視窗高度調整行快取容量
void HexView::ensureLineCacheCapacity()
{
    if (m_lineHeight <= 0) {
        m_lineCache.clear();
        m_nextCacheSlot = 0;
        return;
    }

    int linesPerPage = qMax(1, (viewport()->height() - m_topMargin * 2) / m_lineHeight);
    int desired = linesPerPage + 4; // 多留幾行緩衝

    if (desired <= 0) {
        m_lineCache.clear();
        m_nextCacheSlot = 0;
        return;
    }

    if (m_lineCache.size() != desired) {
        m_lineCache.resize(desired);
        for (auto &e : m_lineCache) {
            e.line  = -1;
            e.valid = false;
        }
        m_nextCacheSlot = 0;
    }
}

void HexView::loadData(const QByteArray &data)
{
    m_data = data;
    if (m_data.isEmpty()) {
        m_cursorOffset = 0;
        verticalScrollBar()->setRange(0, 0);
        for (auto &e : m_lineCache) {
            e.line  = -1;
            e.valid = false;
        }
        viewport()->update();
        return;
    }

    if (m_cursorOffset < 0 || m_cursorOffset >= m_data.size())
        m_cursorOffset = 0;

    verticalScrollBar()->setValue(0);
    updateScrollBars();

    // 清空快取，下次畫面自動重建
    for (auto &e : m_lineCache) {
        e.line  = -1;
        e.valid = false;
    }
    viewport()->update();
}

void HexView::setEditable(bool editable)
{
    m_editable = editable;
}

// 取得指定行的影像（如無快取則繪製一張並加入快取）
const QImage &HexView::getLineImage(int line)
{
    // 先在快取中找
    for (auto &e : m_lineCache) {
        if (e.valid && e.line == line) {
            return e.image;
        }
    }

    // 找不到 → 重繪一張並放入下一個可用快取槽
    if (m_lineCache.isEmpty()) {
        ensureLineCacheCapacity();
        if (m_lineCache.isEmpty()) {
            static QImage dummy;
            return dummy;
        }
    }

    LineCacheEntry &slot = m_lineCache[m_nextCacheSlot];
    m_nextCacheSlot = (m_nextCacheSlot + 1) % m_lineCache.size();

    slot.image = renderLineToImage(line);
    slot.line  = line;
    slot.valid = true;

    return slot.image;
}

// 把一行內容畫到 QImage（只畫這一行，不管捲軸）
QImage HexView::renderLineToImage(int line)
{
    if (m_lineHeight <= 0 || viewport()->width() <= 0) {
        return QImage();
    }

    QImage img(viewport()->width(), m_lineHeight, QImage::Format_ARGB32_Premultiplied);
    img.fill(QColor(0x1e, 0x1e, 0x1e));

    QPainter p(&img);
    p.setFont(font());

    int y = m_lineHeight - 2; // baseline

    qint64 base = qint64(line) * m_bytesPerLine;
    int byteCount = m_data.size();

    // 地址欄
    QString addr = QString("%1")
                       .arg(base + m_baseOffset, addressChars(), 16, QLatin1Char('0'))
                       .toUpper();
    p.setPen(QColor(160, 160, 160));
    p.drawText(m_leftMargin, y, addr);

    // 畫 HEX + ASCII
    for (int col = 0; col < m_bytesPerLine; ++col) {
        qint64 off = base + col;
        if (off >= byteCount)
            break;

        unsigned char byte = static_cast<unsigned char>(m_data.at(off));

        int hx = m_hexStartX   + col * m_hexCellWidth;
        int ax = m_asciiStartX + col * m_charWidth;

        QRect hexRect(hx, 0, m_hexCellWidth, m_lineHeight);
        QRect asciiRect(ax, 0, m_charWidth,   m_lineHeight);

        bool isCursor = (off == m_cursorOffset);

        if (isCursor) {
            p.fillRect(hexRect,   QColor(70, 100, 160));
            p.fillRect(asciiRect, QColor(70, 100, 160));
            p.setPen(Qt::white);
        } else {
            p.setPen(QColor(230, 230, 230));
        }

        p.drawText(hexRect,   Qt::AlignLeft | Qt::AlignVCenter, m_hexCache[byte]);
        p.drawText(asciiRect, Qt::AlignLeft | Qt::AlignVCenter, m_asciiCache[byte]);
    }

    return img;
}

void HexView::paintEvent(QPaintEvent *event)
{
    Q_UNUSED(event);

    QPainter p(viewport());
    QRect vpRect = viewport()->rect();
    p.fillRect(vpRect, QColor(0x1e, 0x1e, 0x1e));

    if (m_data.isEmpty() || m_lineHeight <= 0 || m_bytesPerLine <= 0)
        return;

    int vpos = verticalScrollBar()->value();

    int linesPerPage = qMax(1, (viewport()->height() - m_topMargin * 2) / m_lineHeight);
    int byteCount    = m_data.size();
    int totalLines   = (byteCount + m_bytesPerLine - 1) / m_bytesPerLine;
    int lastLine     = qMin(vpos + linesPerPage, totalLines);

    for (int line = vpos; line < lastLine; ++line) {
        int y = m_topMargin + (line - vpos) * m_lineHeight;
        const QImage &img = getLineImage(line);
        if (!img.isNull()) {
            p.drawImage(0, y, img);
        }
    }
}

void HexView::resizeEvent(QResizeEvent *event)
{
    QAbstractScrollArea::resizeEvent(event);

    updateMetrics();

    // 視窗大小改變 → 目前快取行內容不再準確 → 全部無效
    for (auto &e : m_lineCache) {
        e.line  = -1;
        e.valid = false;
    }

    viewport()->update();
}

void HexView::wheelEvent(QWheelEvent *event)
{
    int delta = event->angleDelta().y();
    if (delta == 0) {
        QAbstractScrollArea::wheelEvent(event);
        return;
    }

    double steps = double(delta) / 120.0;
    int lines = -qRound(steps); // 滾輪往上 delta>0 → 往下捲 1 行

    QScrollBar *v = verticalScrollBar();
    int newVal = v->value() + lines;
    newVal = qBound(v->minimum(), newVal, v->maximum());
    if (newVal != v->value()) {
        v->setValue(newVal);

        // 捲動時，原則上只會有新的行出現，快取可以漸進更新
        // 這裡我們簡單做：不清快取，但下一次 getLineImage 需要時會補
    }

    event->accept();
    viewport()->update();
}

QSize HexView::sizeHint() const
{
    int lines = 16;
    int width = 600;
    if (m_charWidth > 0 && m_hexCellWidth > 0) {
        int addrWidth   = addressChars() * m_charWidth;
        int gapAddrHex  = m_charWidth * 2;
        int gapHexAscii = m_charWidth * 2;
        int rightMargin = m_leftMargin;
        width = m_leftMargin + addrWidth + gapAddrHex
                + m_bytesPerLine * (m_hexCellWidth + m_charWidth)
                + gapHexAscii + rightMargin;
    }
    int height = m_topMargin * 2 + lines * (m_lineHeight > 0 ? m_lineHeight : 16);
    return QSize(width, height);
}

QSize HexView::minimumSizeHint() const
{
    return QSize(200, 100);
}

void HexView::ensureVisible(qint64 offset)
{
    if (offset < 0 || m_data.isEmpty() || m_bytesPerLine <= 0)
        return;

    int line = int(offset / m_bytesPerLine);
    QScrollBar *v = verticalScrollBar();

    int firstLine    = v->value();
    int linesPerPage = v->pageStep();
    if (linesPerPage <= 0) linesPerPage = 1;

    int lastLine = firstLine + linesPerPage - 1;

    if (line < firstLine)
        v->setValue(line);
    else if (line > lastLine)
        v->setValue(line - linesPerPage + 1);
}

void HexView::moveCursorRelative(qint64 deltaBytes)
{
    if (m_data.isEmpty())
        return;

    qint64 newOff = m_cursorOffset + deltaBytes;
    if (newOff < 0) newOff = 0;
    if (newOff >= m_data.size()) newOff = m_data.size() - 1;

    if (newOff == m_cursorOffset)
        return;

    m_cursorOffset = newOff;
    ensureVisible(m_cursorOffset);

    // 游標位置變了，對應行的快取要重畫（避免 highlight 位置錯誤）
    for (auto &e : m_lineCache) {
        if (e.valid && (e.line == int(m_cursorOffset / m_bytesPerLine) ||
                        e.line == int((m_cursorOffset - deltaBytes) / m_bytesPerLine))) {
            e.valid = false;
        }
    }

    viewport()->update();
}

void HexView::moveCursorLineRelative(qint64 deltaLines)
{
    moveCursorRelative(deltaLines * m_bytesPerLine);
}

void HexView::moveCursorToLineStart()
{
    if (m_data.isEmpty())
        return;

    qint64 line = m_cursorOffset / m_bytesPerLine;
    qint64 newOff = line * m_bytesPerLine;
    if (newOff >= m_data.size())
        newOff = m_data.size() - 1;

    moveCursorRelative(newOff - m_cursorOffset);
}

void HexView::moveCursorToLineEnd()
{
    if (m_data.isEmpty())
        return;

    qint64 line = m_cursorOffset / m_bytesPerLine;
    qint64 newOff = line * m_bytesPerLine + (m_bytesPerLine - 1);
    if (newOff >= m_data.size())
        newOff = m_data.size() - 1;

    moveCursorRelative(newOff - m_cursorOffset);
}

void HexView::handleHexEdit(QKeyEvent *event)
{
    if (!m_editable || m_data.isEmpty())
        return;

    QString txt = event->text();
    if (txt.isEmpty())
        return;
    QChar c = txt.at(0);

    auto hexVal = [](QChar ch) -> int {
        if (ch >= '0' && ch <= '9') return ch.unicode() - '0';
        if (ch >= 'a' && ch <= 'f') return ch.unicode() - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch.unicode() - 'A' + 10;
        return -1;
    };

    int v = hexVal(c);
    if (v < 0)
        return;

    static bool highNibble = true;

    unsigned char oldByte = static_cast<unsigned char>(m_data.at(m_cursorOffset));
    unsigned char newByte;

    if (highNibble) {
        newByte = static_cast<unsigned char>((v << 4) | (oldByte & 0x0F));
    } else {
        newByte = static_cast<unsigned char>((oldByte & 0xF0) | v);
    }

    m_data[m_cursorOffset] = char(newByte);
    highNibble = !highNibble;

    // 編輯會影響當前行快取
    int line = int(m_cursorOffset / m_bytesPerLine);
    for (auto &e : m_lineCache) {
        if (e.valid && e.line == line) {
            e.valid = false;
        }
    }

    if (highNibble) {
        // 高位 + 低位輸入完 → 游標往下一個 byte
        moveCursorRelative(1);
    } else {
        viewport()->update();
    }
}

void HexView::keyPressEvent(QKeyEvent *event)
{
    if (event->modifiers() & (Qt::ControlModifier | Qt::AltModifier | Qt::MetaModifier)) {
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

    handleHexEdit(event);
}

void HexView::mousePressEvent(QMouseEvent *event)
{
    if (event->button() != Qt::LeftButton)
        return;

    int vpos = verticalScrollBar()->value();
    int y = event->pos().y() - m_topMargin;
    if (y < 0 || m_lineHeight <= 0)
        return;

    int lineOffset = y / m_lineHeight;
    int line = vpos + lineOffset;
    qint64 base = qint64(line) * m_bytesPerLine;
    if (base >= m_data.size())
        return;

    int x = event->pos().x();
    qint64 col = -1;

    if (x >= m_hexStartX && x < m_hexStartX + m_bytesPerLine * m_hexCellWidth)
        col = (x - m_hexStartX) / m_hexCellWidth;
    else if (x >= m_asciiStartX && x < m_asciiStartX + m_bytesPerLine * m_charWidth)
        col = (x - m_asciiStartX) / m_charWidth;
    else
        return;

    qint64 off = base + col;
    if (off >= m_data.size())
        off = m_data.size() - 1;

    m_cursorOffset = off;
    ensureVisible(m_cursorOffset);

    // 點擊切換行 → 當前行快取重畫
    int curLine = int(m_cursorOffset / m_bytesPerLine);
    for (auto &e : m_lineCache) {
        if (e.valid && e.line == curLine) {
            e.valid = false;
        }
    }

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
        int pos = m_data.indexOf(pattern);
        while (pos >= 0 && pos <= start) {
            found = pos;
            pos = m_data.indexOf(pattern, pos + 1);
        }
    }

    if (found >= 0) {
        qint64 oldLine = m_cursorOffset / m_bytesPerLine;
        m_cursorOffset = found;
        ensureVisible(m_cursorOffset);
        qint64 newLine = m_cursorOffset / m_bytesPerLine;

        for (auto &e : m_lineCache) {
            if (!e.valid) continue;
            if (e.line == oldLine || e.line == newLine) {
                e.valid = false;
            }
        }

        viewport()->update();
    }

    return found;
}

void HexView::gotoOffset(qint64 offset)
{
    if (m_data.isEmpty())
        return;

    if (offset < 0) offset = 0;
    if (offset >= m_data.size()) offset = m_data.size() - 1;

    qint64 oldLine = m_cursorOffset / m_bytesPerLine;
    m_cursorOffset = offset;
    ensureVisible(m_cursorOffset);
    qint64 newLine = m_cursorOffset / m_bytesPerLine;

    for (auto &e : m_lineCache) {
        if (!e.valid) continue;
        if (e.line == oldLine || e.line == newLine) {
            e.valid = false;
        }
    }

    viewport()->update();
}

qint64 HexView::offsetFromIndex(const QModelIndex &idx) const
{
    Q_UNUSED(idx);
    return m_cursorOffset;
}

QModelIndex HexView::currentIndex() const
{
    return QModelIndex();
}

qint64 HexView::currentOffset() const
{
    return m_cursorOffset;
}
