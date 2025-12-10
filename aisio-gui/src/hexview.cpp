#include "../include/hexview.h"

#include <QPainter>
#include <QScrollBar>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QShortcut>
#include <QFontDatabase>
#include <QtMath>
#include <QDebug>
#include <QGuiApplication>
#include <QClipboard>
#include <QMimeData>
#include <algorithm>
#include <QTimer>

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

    new QShortcut(QKeySequence("Ctrl+Z"), this, [this](){ this->undo(); });
    new QShortcut(QKeySequence("Ctrl+Y"), this, [this](){ this->redo(); });
    new QShortcut(QKeySequence("Ctrl+C"), this, [this](){ this->copySelectionToClipboard(); });
    new QShortcut(QKeySequence("Ctrl+V"), this, [this](){ this->pasteFromClipboard(); });

    m_errorFlashTimer = new QTimer(this);
    m_errorFlashTimer->setInterval(60);
    connect(m_errorFlashTimer, &QTimer::timeout, this, [this] {
        if (m_errorFlashCounter > 0) {
            m_errorFlashCounter--;
            invalidateAllLines();
            viewport()->update();
        } else {
            m_errorFlashTimer->stop();
        }
    });

    updateMetrics();
}

// 依視窗寬度 + 字體度量決定每行顯示多少 bytes
void HexView::recalcBytesPerLineForWidth(int viewportWidth)
{
    Q_UNUSED(viewportWidth);

    if (m_charWidth <= 0 || m_hexCellWidth <= 0)
        return;

    // 問題 4：固定每行 0x10 bytes
    m_bytesPerLine = 0x10;

    const int gapAddrHex  = m_charWidth * 2; // 地址與 HEX 間距
    const int gapHexAscii = m_charWidth * 2; // HEX 與 ASCII 間距

    int addrWidth = addressChars() * m_charWidth;

    m_hexStartX   = m_leftMargin + addrWidth + gapAddrHex;
    m_asciiStartX = m_hexStartX + m_bytesPerLine * m_hexCellWidth + gapHexAscii;
}

// 清空選取
void HexView::clearSelectionRange()
{
    m_selStart = -1;
    m_selEnd   = -1;
    m_selAnchor = -1;
}

// 設定選取範圍 (自動排序)
void HexView::setSelectionRange(qint64 start, qint64 end)
{
    if (start < 0) start = 0;
    if (end < start) end = start;

    m_selStart = start;
    m_selEnd   = end;

    // 選取改變 → 重畫
    invalidateAllLines();
    viewport()->update();
}

qint64 HexView::clickedOffset(const QPoint &p)
{
    if (m_data.isEmpty() || m_lineHeight <= 0)
        return -1;

    int vpos = verticalScrollBar()->value();

    // Y → 行號
    int y = p.y() - m_topMargin;
    if (y < 0) return -1;

    int lineOffset = y / m_lineHeight;
    int line = vpos + lineOffset;

    qint64 base = qint64(line) * m_bytesPerLine;
    if (base >= m_data.size()) return -1;

    // X → HEX/ASCII 欄位
    int x = p.x();

    // HEX 區
    if (x >= m_hexStartX && x < m_hexStartX + m_bytesPerLine * m_hexCellWidth)
    {
        lastClickArea = Area::Hex;
        int col = (x - m_hexStartX) / m_hexCellWidth;
        qint64 off = base + col;
        return (off < m_data.size()) ? off : m_data.size() - 1;
    }

    // ASCII 區
    if (x >= m_asciiStartX && x < m_asciiStartX + m_bytesPerLine * m_charWidth)
    {
        lastClickArea = Area::Ascii;
        int col = (x - m_asciiStartX) / m_charWidth;
        qint64 off = base + col;
        return (off < m_data.size()) ? off : m_data.size() - 1;
    }

    return -1;
}

void HexView::pushEdit(qint64 offset, quint8 oldByte, quint8 newByte)
{
    m_undoStack.append({offset, oldByte, newByte});
    m_redoStack.clear();
}

void HexView::undo()
{
    if (m_undoStack.isEmpty())
        return;

    Edit e = m_undoStack.takeLast();
    m_redoStack.append(e);

    m_data[e.offset] = char(e.oldByte);
    m_cursorOffset = e.offset;

    invalidateAllLines();
    viewport()->update();
}

void HexView::redo()
{
    if (m_redoStack.isEmpty())
        return;

    Edit e = m_redoStack.takeLast();
    m_undoStack.append(e);

    m_data[e.offset] = char(e.newByte);
    m_cursorOffset = e.offset;

    invalidateAllLines();
    viewport()->update();
}

void HexView::updateSelectionAfterCursorMove()
{
    if (m_selAnchor < 0)
        return;

    qint64 start = qMin(m_selAnchor, m_cursorOffset);
    qint64 end   = qMax(m_selAnchor, m_cursorOffset) + 1;
    setSelectionRange(start, end);
}

bool HexView::byteInAnySelection(qint64 off) const
{
    if (m_selStart >= 0 && off >= m_selStart && off < m_selEnd)
        return true;

    for (const auto &r : m_extraSelections) {
        if (off >= r.start && off < r.end)
            return true;
    }
    return false;
}

QVector<HexView::Range> HexView::allSelectionsNormalized() const
{
    QVector<Range> ranges;

    if (m_selStart >= 0 && m_selEnd > m_selStart)
        ranges.append(Range{m_selStart, m_selEnd});

    for (const auto &r : m_extraSelections) {
        if (r.end > r.start)
            ranges.append(r);
    }

    if (ranges.isEmpty())
        return ranges;

    std::sort(ranges.begin(), ranges.end(),
              [](const Range &a, const Range &b){ return a.start < b.start; });

    QVector<Range> merged;
    Range cur = ranges[0];
    for (int i = 1; i < ranges.size(); ++i) {
        const Range &r = ranges[i];
        if (r.start <= cur.end) {
            // 重疊或相接 → 合併
            if (r.end > cur.end)
                cur.end = r.end;
        } else {
            merged.append(cur);
            cur = r;
        }
    }
    merged.append(cur);
    return merged;
}

void HexView::copySelectionToClipboard()
{
    bool inHexArea = (lastClickArea == Area::Hex);
    bool inAsciiArea = (lastClickArea == Area::Ascii);

    QVector<Range> ranges = allSelectionsNormalized();
    if (ranges.isEmpty() || m_data.isEmpty())
        return;

    QByteArray bytes;

    for (const auto &r : ranges) {
        qint64 s = qMax<qint64>(0, r.start);
        qint64 e = qMin<qint64>(m_data.size(), r.end);
        for (qint64 i = s; i < e; ++i) {
            bytes.append(m_data.at(i));
        }
    }

    if (bytes.isEmpty())
        return;

    QClipboard *cb = QGuiApplication::clipboard();
    if (!cb)
        return;

    // -------------------------------
    // ⭐ 1) 使用者從 HEX 區複製 → HEX 字串
    // -------------------------------
    if (inHexArea)
    {
        QString hex;
        hex.reserve(bytes.size() * 3);

        for (int i = 0; i < bytes.size(); ++i) {
            unsigned char b = static_cast<unsigned char>(bytes.at(i));
            hex += QString("%1").arg(b, 2, 16, QLatin1Char('0')).toUpper();
            if (i + 1 < bytes.size())
                hex += QLatin1Char(' ');
        }

        cb->setText(hex);
        return;
    }

    // -------------------------------
    // ⭐ 2) 使用者從 ASCII 區複製 → ASCII 字串
    // -------------------------------
    if (inAsciiArea)
    {
        QString ascii;
        ascii.reserve(bytes.size());

        for (int i = 0; i < bytes.size(); ++i) {
            unsigned char b = static_cast<unsigned char>(bytes.at(i));

            if (b >= 0x20 && b <= 0x7E) {
                ascii += QChar(b);     // 可印字元
            } else {
                ascii += QChar('.');   // 不可印字元 → 以 '.' 代替
            }
        }

        cb->setText(ascii);
        return;
    }

    // -------------------------------
    // ⭐ 如果區域未知 → 預設 HEX
    // -------------------------------
    QString fallback;
    fallback.reserve(bytes.size() * 3);

    for (int i = 0; i < bytes.size(); ++i) {
        unsigned char b = static_cast<unsigned char>(bytes.at(i));
        fallback += QString("%1").arg(b, 2, 16, QLatin1Char('0')).toUpper();
        if (i + 1 < bytes.size())
            fallback += QLatin1Char(' ');
    }

    cb->setText(fallback);
}

void HexView::pasteFromClipboard()
{
    if (m_data.isEmpty())
        return;

    const QClipboard *cb = QGuiApplication::clipboard();
    if (!cb)
        return;

    QString text = cb->text();
    if (text.isEmpty())
        return;

    // 解析 hex：抓連續兩個 hex 字元為一個 byte
    auto hexVal = [](QChar ch) -> int {
        if (ch >= '0' && ch <= '9') return ch.unicode() - '0';
        QChar up = ch.toUpper();
        if (up >= 'A' && up <= 'F') return up.unicode() - 'A' + 10;
        return -1;
    };

    QByteArray bytes;
    for (int i = 0; i < text.size();) {
        while (i < text.size() && hexVal(text.at(i)) < 0)
            ++i;
        if (i + 1 >= text.size())
            break;

        int v1 = hexVal(text.at(i));
        int v2 = hexVal(text.at(i + 1));
        if (v1 < 0 || v2 < 0) {
            ++i;
            continue;
        }
        unsigned char b = static_cast<unsigned char>((v1 << 4) | v2);
        bytes.append(char(b));
        i += 2;
    }

    if (bytes.isEmpty())
        return;

    // 貼上的起點：如果有主選取，就從 m_selStart 開始；否則從游標
    qint64 pos = (m_selStart >= 0 && m_selEnd > m_selStart) ? m_selStart : m_cursorOffset;
    if (pos < 0) pos = 0;
    if (pos >= m_data.size()) pos = m_data.size() - 1;

    int maxWrite = qMin<qint64>(bytes.size(), m_data.size() - pos);

    for (int i = 0; i < maxWrite; ++i) {
        qint64 off = pos + i;
        unsigned char oldByte = static_cast<unsigned char>(m_data.at(off));
        unsigned char newByte = static_cast<unsigned char>(bytes.at(i));
        if (oldByte == newByte)
            continue;
        pushEdit(off, oldByte, newByte);
        m_data[off] = char(newByte);
    }

    m_cursorOffset = qMin<qint64>(pos + maxWrite - 1, m_data.size() - 1);

    // 貼上後清選取
    clearSelectionRange();
    m_extraSelections.clear();

    invalidateAllLines();
    viewport()->update();
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

void HexView::invalidateAllLines()
{
    for (auto &e : m_lineCache) {
        e.line  = -1;
        e.valid = false;
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

        bool hasSel = (m_selStart >= 0 && m_selEnd > m_selStart) ||
                      !m_extraSelections.isEmpty();

        bool inSelection = byteInAnySelection(off);

        // 如果有選取 → 不畫游標
        bool isCursor = (!hasSel && m_showCursor && off == m_cursorOffset);


        if (m_errorFlashCounter > 0 && off == m_cursorOffset) {
            p.fillRect(hexRect, QColor(255, 80, 80, 160));
            p.fillRect(asciiRect, QColor(255, 80, 80, 160));
            p.setPen(Qt::white);
        }
        else if (inSelection) {
            p.fillRect(hexRect, QColor(100, 130, 200));
            p.fillRect(asciiRect, QColor(100, 130, 200));
            p.setPen(Qt::white);
        }
        else if (isCursor) {
            p.fillRect(hexRect, QColor(70, 100, 160));
            p.fillRect(asciiRect, QColor(70, 100, 160));
            p.setPen(Qt::white);
        }
        else {
            p.setPen(QColor(230,230,230));
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
    m_showCursor = true;
    if (!(QGuiApplication::keyboardModifiers() & Qt::ShiftModifier)) {
        clearSelectionRange();
        m_extraSelections.clear();
    }

    if (m_data.isEmpty())
        return;

    qint64 newOff = m_cursorOffset + deltaBytes;
    if (newOff < 0) newOff = 0;
    if (newOff >= m_data.size()) newOff = m_data.size() - 1;

    if (newOff == m_cursorOffset)
        return;

    m_cursorOffset = newOff;
    ensureVisible(m_cursorOffset);
    // 游標位置變了，整個行快取無效化，避免殘留高亮
    invalidateAllLines();
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

bool HexView::handleHexEdit(QKeyEvent *event)
{
    if (!m_editable || m_data.isEmpty())
        return false;

    QString txt = event->text();
    if (txt.isEmpty())
        return false;
    QChar c = txt.at(0);

    auto hexVal = [](QChar ch) -> int {
        if (ch >= '0' && ch <= '9') return ch.unicode() - '0';
        if (ch >= 'a' && ch <= 'f') return ch.unicode() - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch.unicode() - 'A' + 10;
        return -1;
    };

    int v = hexVal(c);
    if (v < 0) {
        // ⭐ 無效 hex → 不動游標，不動 highNibble
        flashError();
        return false;
    }

    static bool highNibble = true;

    unsigned char oldByte = static_cast<unsigned char>(m_data.at(m_cursorOffset));
    unsigned char newByte;

    if (highNibble) {
        newByte = static_cast<unsigned char>((v << 4) | (oldByte & 0x0F));
    } else {
        newByte = static_cast<unsigned char>((oldByte & 0xF0) | v);
    }
    pushEdit(m_cursorOffset, oldByte, newByte);

    m_data[m_cursorOffset] = char(newByte);
    highNibble = !highNibble;

    // ⭐ 編輯後整個快取無效化，避免殘留錯誤 highlight
    invalidateAllLines();

    if (highNibble) {
        // 高位 + 低位輸入完 → 游標往下一個 byte
        moveCursorRelative(1);
    }
    viewport()->update();
    return true;
}

bool HexView::handleAsciiEdit(QKeyEvent *event)
{
    if (!m_editable || m_data.isEmpty())
        return false;

    QString txt = event->text();
    QChar c(0x00);

    // text 可靠時使用 text
    if (!txt.isEmpty()) {
        c = txt.at(0);
    } else {
        // fallback：用 key() 推算 ASCII 字元
        int k = event->key();
        if (k >= 0x20 && k <= 0x7F)
            c = QChar(k);
    }

    // still invalid?
    if (c.unicode() < 0x20 || c.unicode() > 0x7F) {
        return false;
    }

    unsigned char oldByte = static_cast<unsigned char>(m_data[m_cursorOffset]);
    unsigned char newByte = static_cast<unsigned char>(c.unicode());

    pushEdit(m_cursorOffset, oldByte, newByte);
    m_data[m_cursorOffset] = char(newByte);

    invalidateAllLines();
    moveCursorRelative(1);
    viewport()->update();
    return true;
}

void HexView::flashError()
{
    m_errorFlashCounter = 3;
    invalidateAllLines();
    viewport()->update();
    m_errorFlashTimer->start();
}

void HexView::keyPressEvent(QKeyEvent *event)
{
    bool inHexArea = (lastClickArea == Area::Hex);
    bool inAsciiArea = (lastClickArea == Area::Ascii);

    if (event->modifiers() & (Qt::AltModifier | Qt::MetaModifier)) {
        QAbstractScrollArea::keyPressEvent(event);
        return;
    }

    if (event->key() == Qt::Key_Escape) {
        bool hadSelection = hasSelection() || !m_extraSelections.isEmpty();

        clearSelectionRange();
        m_extraSelections.clear();
        m_showCursor = false;
        invalidateAllLines();
        viewport()->update();

        if (hadSelection)
        {
            // 保留在 HexView → 不傳到 HexForm
            event->accept();
            return;
        }

        // 沒有任何選取時 → 讓 HexForm 收到 ESC
        event->ignore();
        return;
    }

    if (event->modifiers() & Qt::ShiftModifier)
    {
        if (inAsciiArea && handleAsciiEdit(event))
            return;

        qint64 oldCursor = m_cursorOffset;

        // 依方向鍵移動 cursor
        switch (event->key()) {
        case Qt::Key_Left:   moveCursorRelative(-1); break;
        case Qt::Key_Right:  moveCursorRelative( 1); break;
        case Qt::Key_Up:     moveCursorLineRelative(-1); break;
        case Qt::Key_Down:   moveCursorLineRelative( 1); break;
        default:return; // 不處理非方向鍵
        }

        qint64 newCursor = m_cursorOffset;

        if (m_selAnchor < 0)
            m_selAnchor = oldCursor;

        if (newCursor >= m_selAnchor)
            setSelectionRange(m_selAnchor, newCursor + 1);
        else
            setSelectionRange(newCursor, m_selAnchor + 1);

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

    if (inHexArea) {
        handleHexEdit(event);
        return;
    } else if (inAsciiArea) {
        handleAsciiEdit(event);
        return;
    }

    if (m_errorFlashCounter > 0)
        m_errorFlashCounter--;
}

void HexView::mousePressEvent(QMouseEvent *event)
{
    if (event->button() != Qt::LeftButton) {
        QAbstractScrollArea::mousePressEvent(event);
        return;
    }

    qint64 clickOff = clickedOffset(event->pos());
    if (clickOff < 0) {
        QAbstractScrollArea::mousePressEvent(event);
        return;
    }

    bool shift = event->modifiers() & Qt::ShiftModifier;
    bool ctrl  = event->modifiers() & Qt::ControlModifier;

    qint64 oldCursor = m_cursorOffset;
    m_cursorOffset = clickOff;
    ensureVisible(m_cursorOffset);

    // --- Ctrl：多段選取 toggle ---
    if (ctrl) {
        // 檢查是否已在主選取或額外選取中
        bool inMain = (m_selStart >= 0 && clickOff >= m_selStart && clickOff < m_selEnd);
        bool removed = false;

        for (int i = 0; i < m_extraSelections.size(); ++i) {
            const auto &r = m_extraSelections[i];
            if (clickOff >= r.start && clickOff < r.end) {
                m_extraSelections.removeAt(i);
                removed = true;
                break;
            }
        }

        if (!inMain && !removed) {
            // 新增一個 1-byte 的額外選取
            Range r;
            r.start = clickOff;
            r.end   = clickOff + 1;
            m_extraSelections.append(r);
        }

        invalidateAllLines();
        viewport()->update();
        return;
    }

    // --- Shift：從 anchor 延伸到 clickOff ---
    if (shift) {
        if (m_selAnchor < 0)
            m_selAnchor = oldCursor; // 第一次 Shift-click，以舊游標當 anchor

        qint64 start = qMin(m_selAnchor, clickOff);
        qint64 end   = qMax(m_selAnchor, clickOff) + 1;
        setSelectionRange(start, end);
        return;
    }

    // --- 一般左鍵：開始新的單一選取，清除所有額外選取 ---
    m_dragSelecting = true;
    m_selAnchor = m_cursorOffset;
    m_selStart  = m_cursorOffset;
    m_selEnd    = m_cursorOffset + 1;
    m_extraSelections.clear();

    invalidateAllLines();
    viewport()->update();
}

void HexView::mouseMoveEvent(QMouseEvent *event)
{
    if (!m_dragSelecting)
        return;

    qint64 off = clickedOffset(event->pos());
    if (off >= 0)
    {
        if (off >= m_selAnchor)
            setSelectionRange(m_selAnchor, off + 1);
        else
            setSelectionRange(off, m_selAnchor + 1);

        m_cursorOffset = off;
        ensureVisible(m_cursorOffset);
    }
}

void HexView::mouseReleaseEvent(QMouseEvent *event)
{
    if (event->button() == Qt::LeftButton)
        m_dragSelecting = false;
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

        // ⭐ 設選取 = 整個 pattern 範圍
        m_selStart = found;
        m_selEnd   = found + pattern.size();
        m_selAnchor = found;
        m_extraSelections.clear();

        // ⭐ 游標移到起點，並啟用 cursor（如果想）
        m_cursorOffset = found;
        m_showCursor = false; // 或 true，看你的偏好

        ensureVisible(found);

        invalidateAllLines();
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

    // ⭐ 直接清掉快取，避免舊行殘影
    invalidateAllLines();
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
