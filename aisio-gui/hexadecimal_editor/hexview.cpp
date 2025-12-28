#include "hexview.h"
#include "interpretvaluedelegate.h"

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
#include <QRegularExpression>
#include <QInputDialog>
#include <QMessageBox>

#include <QLineEdit>
#include <QComboBox>
#include <QToolButton>
#include <QHBoxLayout>
#include <QLabel>
#include <QFile>
#include <QTableWidget>
#include <QHeaderView>
#include <QVBoxLayout>
#include <QDateTime>
#include <QMenu>

#include <QStyledItemDelegate>
#include <QEvent>

#if __has_include(<capstone/capstone.h>)
#include <capstone/capstone.h>
#define HEXVIEW_HAVE_CAPSTONE 1
#else
#define HEXVIEW_HAVE_CAPSTONE 0
#endif

HexView::HexView(QWidget *parent)
    : QAbstractScrollArea(parent)
{
    // 用系統等寬字型
    QFont f("JetBrains Mono");
    if (!QFontInfo(f).fixedPitch()) {
        f = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    }
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

    m_errorFlashTimer = new QTimer(this);
    m_errorFlashTimer->setInterval(60);
    connect(m_errorFlashTimer, &QTimer::timeout, this, [this] {
        bool needUpdate = false;

        if (m_editFlashCounter > 0) {
            m_editFlashCounter--;
            needUpdate = true;
        }
        if (m_searchFlashCounter > 0) {
            m_searchFlashCounter--;
            needUpdate = true;
        }

        if (needUpdate) {
            invalidateAllLines();
            viewport()->update();
        } else {
            m_errorFlashTimer->stop();
        }
    });

    m_lineEditFlashTimer = new QTimer(this);
    m_lineEditFlashTimer->setInterval(120);
    connect(m_lineEditFlashTimer, &QTimer::timeout, this, [this]() {
        if (!m_lineEditFlashing) {
            m_lineEditFlashTimer->stop();
            return;
        }

        m_lineEditFlashCount--;

        if (m_lineEditFlashCount < 0) {
            m_lineEditFlashing->setProperty("flashError", false);
            m_lineEditFlashing->style()->unpolish(m_lineEditFlashing);
            m_lineEditFlashing->style()->polish(m_lineEditFlashing);
            m_lineEditFlashing = nullptr;
            m_lineEditFlashTimer->stop();
            return;
        }

        bool on = (m_lineEditFlashCount % 2) == 0;
        m_lineEditFlashing->setProperty("flashError", on);
        m_lineEditFlashing->style()->unpolish(m_lineEditFlashing);
        m_lineEditFlashing->style()->polish(m_lineEditFlashing);
    });

    updateMetrics();
    createSearchPanel();
    setupSearchShortcuts();
    createInterpretPanel();
    setupInterpretShortcuts();
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

qint64 HexView::scrollResolution() const {
    qint64 byteCount = effectiveSize();
    qint64 totalLines = (byteCount + m_bytesPerLine - 1) / m_bytesPerLine;

    // 小檔案：1 行 = 1 單位（手感最佳）
    if (totalLines <= INT_MAX)
        return totalLines;

    // 大檔案：退化成比例模式
    return 1000000;
}

// 清空選取
void HexView::clearSelectionRange()
{
    m_selStart = -1;
    m_selEnd   = -1;
    m_selAnchor = -1;

    if (m_interpretPanel && m_interpretPanel->isVisible())
        updateInterpretPanel();
}

// 設定選取範圍 (自動排序)
void HexView::setSelectionRange(qint64 start, qint64 end)
{
    if (start < 0) start = 0;
    if (end < start) end = start;

    m_selStart = start;
    m_selEnd   = end;

    if (m_interpretPanel && m_interpretPanel->isVisible())
        updateInterpretPanel();

    // 選取改變 → 重畫
    invalidateAllLines();
    viewport()->update();
}

qint64 HexView::clickedOffset(const QPoint &p)
{
    qint64 byteCount = effectiveSize();

    if (!m_chunks || byteCount <= 0 || m_lineHeight <= 0)
        return -1;

    QFontMetrics fm(font());
    int headerHeight = fm.height();

    // int vpos = verticalScrollBar()->value();
    qint64 vpos = lineFromScroll();

    // Y → 行號
    qint64 y = p.y() - headerHeight - m_topMargin;
    if (y < 0) return -1;

    qint64 lineOffset = y / m_lineHeight;
    qint64 line = vpos + lineOffset;

    qint64 base = qint64(line) * m_bytesPerLine;
    if (base >= byteCount) return -1;

    // X → HEX/ASCII 欄位
    int x = p.x();

    // HEX 區
    if (x >= m_hexStartX && x < m_hexStartX + m_bytesPerLine * m_hexCellWidth)
    {
        lastClickArea = Area::Hex;
        int col = (x - m_hexStartX) / m_hexCellWidth;
        qint64 off = base + col;
        return (off < byteCount) ? off : byteCount - 1;
    }

    // ASCII 區
    if (x >= m_asciiStartX && x < m_asciiStartX + m_bytesPerLine * m_charWidth)
    {
        lastClickArea = Area::Ascii;
        qint64 col = (x - m_asciiStartX) / m_charWidth;
        qint64 off = base + col;
        return (off < byteCount) ? off : byteCount - 1;
    }

    return -1;
}

void HexView::pushEdit(Edit::Type type,
                       qint64 offset,
                       const QByteArray &oldData,
                       const QByteArray &newData)
{
    m_undoStack.append(Edit{type, offset, oldData, newData});
    m_redoStack.clear();
}

void HexView::pushReplaceByte(qint64 offset, uchar oldByte, uchar newByte)
{
    if (oldByte == newByte)
        return;

    pushEdit(Edit::Type::Replace,
             offset,
             QByteArray(1, char(oldByte)),
             QByteArray(1, char(newByte)));
}

void HexView::pushInsertBytes(qint64 offset, const QByteArray &data)
{
    if (data.isEmpty())
        return;

    pushEdit(Edit::Type::Insert,
             offset,
             QByteArray(),
             data);
}

void HexView::pushDeletePieces(qint64 offset, const QVector<OverlayMap::Piece>& pieces, qint64 deleteLen) {
    if (deleteLen <= 0 || pieces.isEmpty())
        return;

    Edit e;
    e.type = Edit::Type::Delete;
    e.offset = offset;
    e.pieces = pieces;
    e.deleteLen = deleteLen;
    e.beforeLen = deleteLen; // undo 後，會插回 deleteLen bytes
    e.afterLen  = 0;         // redo 後，資料被刪掉，沒東西可選
    e.oldData.clear();
    e.newData.clear();

    m_undoStack.append(e);
    m_redoStack.clear();
}

void HexView::undo()
{
    if (m_undoStack.isEmpty())
        return;

    Edit e = m_undoStack.takeLast();
    m_redoStack.append(e);

    switch (e.type){
    case Edit::Type::Replace:
        m_overlay.replace(e.offset, e.oldData, m_chunks);
        m_cursorOffset = e.offset;
        break;
    case Edit::Type::Insert:
        m_overlay.erase(e.offset, e.newData.size());
        m_cursorOffset = e.offset;
        break;
    case Edit::Type::Delete:
        // m_overlay.insert(e.offset, e.oldData);
        m_overlay.insertPieces(e.offset, e.pieces);
        m_cursorOffset = e.offset;
        break;
    default:
        return;
    }

    // 讓游標一定出現在畫面中
    emit cursorChanged(m_cursorOffset);
    emit dataSizeChanged(effectiveSize());
    emit modifiedChanged(true);
    ensureVisible(m_cursorOffset);

    // 重置半位編輯狀態（非常重要）
    m_hexHighNibble = true;

    // 游標一定顯示
    m_showCursor = true;

    // ⭐ Undo / Redo 後，統一回到 Hex 區語意
    lastClickArea = Area::Hex;

    // ⭐ 清掉任何殘留的 selection anchor
    m_selAnchor = -1;
    clearSelectionRange();
    m_extraSelections.clear();

    switch (e.type){
    case Edit::Type::Replace:
    case Edit::Type::Insert:
        m_selStart = e.offset;
        m_selEnd = e.offset + e.newData.size();
        m_selAnchor = e.offset;
        break;
    case Edit::Type::Delete:
        if (e.beforeLen > 0) {
            m_selStart = e.offset;
            m_selEnd   = e.offset + e.beforeLen;
            m_cursorOffset = m_selEnd;
        } else {
            m_selStart = m_selEnd = -1;
            m_cursorOffset = e.offset;
        }
        break;
    }

    invalidateAllLines();
    updateScrollBars();
    viewport()->update();
}

void HexView::redo()
{
    if (m_redoStack.isEmpty())
        return;

    Edit e = m_redoStack.takeLast();
    m_undoStack.append(e);

    switch (e.type){
    case Edit::Type::Replace:
        m_overlay.replace(e.offset, e.newData, m_chunks);
        m_cursorOffset = e.offset;
        break;
    case Edit::Type::Insert:
        m_overlay.insert(e.offset, e.newData);
        m_cursorOffset = e.offset;
        break;
    case Edit::Type::Delete:
        m_overlay.erase(e.offset, e.deleteLen);
        m_cursorOffset = e.offset;
        break;
    default:
        return;
    }

    // 讓游標一定出現在畫面中
    emit cursorChanged(m_cursorOffset);
    emit dataSizeChanged(effectiveSize());
    emit modifiedChanged(true);
    ensureVisible(m_cursorOffset);

    // 重置半位編輯狀態（非常重要）
    m_hexHighNibble = true;

    // 游標一定顯示
    m_showCursor = true;

    // ⭐ Undo / Redo 後，統一回到 Hex 區語意
    lastClickArea = Area::Hex;

    // ⭐ 清掉任何殘留的 selection anchor
    m_selAnchor = -1;
    clearSelectionRange();
    m_extraSelections.clear();

    switch (e.type){
    case Edit::Type::Replace:
    case Edit::Type::Insert:
        m_selStart = e.offset;
        m_selEnd = e.offset + e.newData.size();
        m_selAnchor = e.offset;
        break;
    case Edit::Type::Delete:
        if (e.beforeLen > 0) {
            m_selStart = e.offset;
            m_selEnd   = e.offset + e.afterLen;
            m_cursorOffset = m_selEnd;
        } else {
            m_selStart = m_selEnd = -1;
            m_cursorOffset = e.offset;
        }
        break;
    }

    invalidateAllLines();
    updateScrollBars();
    viewport()->update();
}

QByteArray HexView::parseHexString(const QString &s, bool *ok) const
{
    QString text = s.trimmed();
    if (text.startsWith("0x", Qt::CaseInsensitive))
        text = text.mid(2);

    // 去掉所有空白
    text.remove(QRegularExpression("\\s+"));

    if (text.isEmpty()) {
        if (ok) *ok = false;
        return {};
    }

    if (text.size() % 2 != 0) {
        if (ok) *ok = false;
        return {};
    }

    QByteArray result;
    result.reserve(text.size() / 2);

    for (int i = 0; i < text.size(); i += 2) {
        bool byteOk = false;
        int val = text.mid(i, 2).toInt(&byteOk, 16);
        if (!byteOk || val < 0 || val > 0xFF) {
            if (ok) *ok = false;
            return {};
        }
        result.append(char(val));
    }
    if (ok) *ok = true;
    return result;
}

qint64 HexView::doFindInternal(const QString &input, bool backwards)
{
    QString text = input.trimmed();
    qint64 byteCount = effectiveSize();
    if (text.isEmpty() || !m_chunks || byteCount <= 0)
        return -1;

    // 1) 依 FindMode 解析 pattern
    QByteArray pattern;
    if (m_findMode == FindMode::Hex) {
        bool ok = false;
        pattern = parseHexString(text, &ok);
        if (!ok || pattern.isEmpty())
            return -1;
    } else {
        pattern = text.toUtf8();
        if (pattern.isEmpty())
            return -1;
    }

    // 2) 判斷是否為新的 pattern
    bool newPattern = m_lastPattern.isEmpty() || (pattern != m_lastPattern);

    qint64 start = 0;
    auto clampStart = [&](qint64 v) -> qint64 {
        qint64 byteCount = effectiveSize();
        if (byteCount <= 0) return 0;
        if (v < 0) return 0;
        if (v >= byteCount) return byteCount - 1;
        return v;
    };

    if (!newPattern && m_lastPos >= 0) {
        // 延續同一個 pattern 的搜尋
        start = backwards ? (m_lastPos - 1) : m_lastPos;
        if (start < 0) start = 0;
        start = clampStart(start);
    } else {
        // 新 pattern：以目前游標 / 選取為基準
        if (hasSelection())
            start = backwards ? m_selStart : m_selEnd;
        else
            start = m_cursorOffset;
        start = clampStart(start);
    }

    // 3) 真正執行搜尋（這裡呼叫你原本的 findBytes）
    qint64 pos = findBytes(pattern, start, backwards);
    if (pos >= 0) {
        m_lastPattern = pattern;
        m_lastPos     = pos + (backwards ? 0 : pattern.size());
    }

    if (pos >= 0) {
        // ⭐ 移動游標
        m_cursorOffset = pos;

        // ⭐ 設定 selection（讓使用者「看到」找到的東西）
        m_selAnchor = pos;
        m_selStart  = pos;
        m_selEnd    = pos + pattern.size();

        // ⭐ 搜尋成功 → 黃色閃爍整個選取
        m_searchFlashCounter = 3;
        m_errorFlashTimer->start();

        emit cursorChanged(m_cursorOffset);

        // ⭐ 確保畫面捲動到該位置
        ensureVisible(m_cursorOffset);

        // ⭐ 重設 nibble 狀態（避免編輯時怪怪的）
        m_hexHighNibble = true;

        // ⭐ 記錄 last find position（給 findNext / findPrev 用）
        m_extraSelections.clear();

        // ⭐ 重畫
        invalidateAllLines();
        viewport()->update();
    }

    return pos;
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

void HexView::deleteRanges(const QVector<Range> &ranges)
{
    QVector<Range> rs = ranges;
    std::sort(rs.begin(), rs.end(),
              [](auto &a, auto &b){ return a.start > b.start; });

    for (auto &r : rs) {
        auto pieces = m_overlay.eraseAndReturnPieces(r.start, r.end - r.start);
        pushDeletePieces(r.start, pieces, r.end - r.start);
    }

    // ⭐ 刪除後游標應該回到第一個被刪的位置
    if (!rs.isEmpty()) {
        qint64 newPos = rs.last().start;
        qint64 size = effectiveSize();
        if (newPos >= size)
            newPos = size > 0 ? size - 1 : 0;

        m_cursorOffset = newPos;
        clampCursorToValidRange();
        ensureVisible(m_cursorOffset);
    }

    emit cursorChanged(m_cursorOffset);
    emit dataSizeChanged(effectiveSize());
    emit modifiedChanged(true);

    clearSelectionRange();
    m_extraSelections.clear();
    updateScrollBars();
    invalidateAllLines();
    viewport()->update();
}

void HexView::selectAll() {
    qint64 byteCount = effectiveSize();
    if (!m_chunks || byteCount <= 0) return;
    m_selStart = 0;
    m_selEnd   = byteCount;
    m_selAnchor = 0;
    m_extraSelections.clear();
    invalidateAllLines();
    viewport()->update();
}

void HexView::copySelectionToClipboard()
{
    bool inHexArea = (lastClickArea == Area::Hex);
    bool inAsciiArea = (lastClickArea == Area::Ascii);
    static constexpr qint64 MAX_COPY_BYTES = 0x200000; // 2 MB
    qint64 byteCount = effectiveSize();

    QVector<Range> ranges = allSelectionsNormalized();
    if (ranges.isEmpty() || !m_chunks || byteCount <= 0)
        return;

    qint64 totalLen = 0;
    for (const auto &r : ranges) {
        qint64 s = qMax<qint64>(0, r.start);
        qint64 e = qMin<qint64>(byteCount, r.end);
        if (e > s)
            totalLen += (e - s);
    }

    if (totalLen <= 0)
        return;

    if (totalLen > MAX_COPY_BYTES) {
        QMessageBox box(this);
        box.setStyleSheet("* { background:#222222; color:#f0f0f0; }");
        box.setWindowTitle(tr("Copy failed"));
        box.setText(tr("The selected data (%1 bytes) is too large to copy.\n\n"
                       "Maximum allowed size is %2 bytes.")
                        .arg(totalLen)
                        .arg(MAX_COPY_BYTES));
        box.setIcon(QMessageBox::Warning);
        box.exec();
        return;
    }

    QByteArray bytes;

    for (const auto &r : ranges) {
        qint64 s = qMax<qint64>(0, r.start);
        qint64 e = qMin<qint64>(byteCount, r.end);
        for (qint64 i = s; i < e; ++i) {
            QByteArray one = m_overlay.read(i, 1, m_chunks);
            if (!one.isEmpty())
                bytes.append(one[0]);
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
    // 加入詢問
    PasteMode mode = PasteMode::Insert;
    QMessageBox box(this);
    box.setStyleSheet("* { background:#222222; color:#f0f0f0; }");
    box.setWindowTitle(tr("Paste"));
    box.setText(tr("Paste mode?"));
    box.addButton(tr("Insert"), QMessageBox::AcceptRole);
    box.addButton(tr("Overwrite"), QMessageBox::ActionRole);
    box.addButton(QMessageBox::Cancel);

    box.exec();
    auto role = box.buttonRole(box.clickedButton());

    if (box.clickedButton() == nullptr ||
        role == QMessageBox::NRoles)
        return;
    if (role == QMessageBox::ActionRole)
        mode = PasteMode::Overwrite;
    else if (role != QMessageBox::AcceptRole)
        return;

    if (!m_editable || !m_chunks)
        return;

    QClipboard *cb = QGuiApplication::clipboard();
    if (!cb) return;

    QString text = cb->text();
    if (text.isEmpty())
        return;

    // 依照最後點擊區域決定貼上模式：HEX/ASCII
    const bool inHexArea   = (lastClickArea == Area::Hex);
    const bool inAsciiArea = (lastClickArea == Area::Ascii);

    QByteArray data;

    // QByteArray data = parseHexString(text, nullptr);
    // if (data.isEmpty())
    //     return;

    if (inAsciiArea) {
        // ⭐ ASCII 區：把文字直接轉成 bytes
        // - toLatin1：超出 0x00~0xFF 的字元會變成 '?'
        // - 這符合「貼 ASCII 字串」的直覺
        data = text.toLatin1();
    } else {
        // ⭐ HEX 區（或未知）：當作 hex 字串解析
        bool ok = false;
        data = parseHexString(text, &ok);
        if (!ok || data.isEmpty())
            return;
    }

    if (data.isEmpty())
        return;

    qint64 pos = hasSelection() ? m_selStart : m_cursorOffset;

     qint64 written = 0;

    if (mode == PasteMode::Insert) {
        pushInsertBytes(pos, data);
        m_overlay.insert(pos, data);
        written = data.size();
        m_cursorOffset = written;
    }
    else { // Overwrite
        qint64 maxWrite = qMin<qint64>(data.size(), effectiveSize() - pos);
        if (maxWrite <= 0)
            return;

        QByteArray old = m_overlay.read(pos, maxWrite, m_chunks);
        QByteArray nw  = data.left(maxWrite);

        pushEdit(Edit::Type::Replace, pos, old, nw);
        m_overlay.replace(pos, nw, m_chunks);
        written = maxWrite;
        m_cursorOffset = pos + maxWrite;
    }

    clearSelectionRange();
    m_extraSelections.clear();

    m_selStart = pos;
    m_selEnd   = pos + data.size();
    m_selAnchor = m_cursorOffset;

    emit cursorChanged(m_cursorOffset);
    emit dataSizeChanged(effectiveSize());
    emit modifiedChanged(true);

    updateScrollBars();
    invalidateAllLines();
    viewport()->update();
}

void HexView::createSearchPanel()
{
    m_searchPanel = new QWidget(this);
    m_searchPanel->setAutoFillBackground(true);

    // 簡單深色半透明背景
    QPalette pal = m_searchPanel->palette();
    pal.setColor(QPalette::Window, QColor(40, 40, 40, 230));
    m_searchPanel->setPalette(pal);
    m_searchPanel->setAttribute(Qt::WA_StyledBackground, true);
    m_searchPanel->setStyleSheet(
        "QWidget { border: 1px solid #666666; border-radius: 4px; }"
        "QLineEdit[flashError=\"true\"] { background:#330000; color:#ff8080; }"
        "QComboBox { background-color: #1e1e1e; color: #ffffff; border: 1px solid #555555; }"
        "QToolButton { background-color: #333333; color: #ffffff; border: 1px solid #555555; padding: 0 6px; }"
        "QToolButton:hover { background-color: #444444; }"
        );
    m_searchPanel->installEventFilter(this);

    auto layout = new QHBoxLayout(m_searchPanel);
    layout->setContentsMargins(6, 4, 6, 4);
    layout->setSpacing(4);

    // 模式：Hex / Text
    m_findModeCombo = new QComboBox(m_searchPanel);
    m_findModeCombo->addItem("Hex");
    m_findModeCombo->addItem("Text");

    // Find 欄位
    m_findEdit = new QLineEdit(m_searchPanel);
    m_findEdit->setPlaceholderText(tr("Find..."));

    m_btnFindPrev = new QToolButton(m_searchPanel);
    m_btnFindPrev->setText("◀");

    m_btnFindNext = new QToolButton(m_searchPanel);
    m_btnFindNext->setText("▶");

    // Goto offset 欄位
    m_gotoEdit = new QLineEdit(m_searchPanel);
    m_gotoEdit->setPlaceholderText(tr("Goto offset..."));
    m_gotoEdit->setText(QString("0x"));

    m_btnGoto = new QToolButton(m_searchPanel);
    m_btnGoto->setText(tr("Go"));

    layout->addWidget(m_findModeCombo);
    layout->addWidget(m_findEdit, 1);
    layout->addWidget(m_btnFindPrev);
    layout->addWidget(m_btnFindNext);
    layout->addSpacing(8);
    layout->addWidget(m_gotoEdit);
    layout->addWidget(m_btnGoto);

    m_searchPanel->hide();

    // === 事件綁定 ===

    // 模式切換：Hex / Text
    connect(m_findModeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this](int idx) {
                if (idx == 1)
                    setFindMode(FindMode::Text);
                else
                    setFindMode(FindMode::Hex);
            });

    // Find 文字改變 → 重置搜尋狀態
    connect(m_findEdit, &QLineEdit::textEdited,
            this, [this](const QString &) {
                resetFindState();
            });

    // Next / Prev
    connect(m_btnFindNext, &QToolButton::clicked,
            this, [this]() {
                if (m_findEdit)
                    findNext(m_findEdit->text());
            });
    connect(m_btnFindPrev, &QToolButton::clicked,
            this, [this]() {
                if (m_findEdit)
                    findPrev(m_findEdit->text());
            });

    // 按 Enter 也等於 Next
    connect(m_findEdit, &QLineEdit::returnPressed,
            this, [this]() {
                if (m_findEdit)
                    findNext(m_findEdit->text());
            });

    // Goto
    auto doGoto = [this]() {
        if (!m_gotoEdit) return;
        gotoOffsetFromText(m_gotoEdit->text());
    };
    connect(m_btnGoto, &QToolButton::clicked,
            this, doGoto);
    connect(m_gotoEdit, &QLineEdit::returnPressed,
            this, doGoto);
}

void HexView::positionSearchPanel()
{
    if (!m_searchPanel)
        return;

    // 浮在 viewport 左上角偏 8px 的位置
    if (m_dragOffset.x() == 0 && m_dragOffset.y() == 0) {
        QRect vpRect = viewport()->geometry();
        const int margin = 8;

        QPoint topLeft = QPoint(vpRect.left() + margin,
                                vpRect.top()  + margin);

        m_searchPanel->move(topLeft);
        m_searchPanel->raise();
    }
}

void HexView::setupSearchShortcuts()
{
    auto ctx = Qt::WidgetWithChildrenShortcut;

    // Ctrl+F → 顯示搜尋欄 & 聚焦 Find
    {
        QShortcut *sc = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_F), this);
        sc->setContext(ctx);
        connect(sc, &QShortcut::activated, this, [this]() {
            if (!m_searchPanel) return;
            m_searchPanel->show();
            positionSearchPanel();
            if (m_findEdit) {
                m_findEdit->setFocus();
                m_findEdit->selectAll();
            }
        });
    }

    // F3 → Find Next
    {
        QShortcut *sc = new QShortcut(QKeySequence(Qt::Key_F3), this);
        sc->setContext(ctx);
        connect(sc, &QShortcut::activated, this, [this]() {
            if (!m_searchPanel) return;

            if (m_findEdit && !m_findEdit->text().isEmpty()) {
                findNext(m_findEdit->text());
            } else {
                m_searchPanel->show();
                positionSearchPanel();
                if (m_findEdit)
                    m_findEdit->setFocus();
            }
        });
    }

    // Shift+F3 → Find Prev
    {
        QShortcut *sc = new QShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F3), this);
        sc->setContext(ctx);
        connect(sc, &QShortcut::activated, this, [this]() {
            if (!m_searchPanel) return;

            if (m_findEdit && !m_findEdit->text().isEmpty()) {
                findPrev(m_findEdit->text());
            } else {
                m_searchPanel->show();
                positionSearchPanel();
                if (m_findEdit)
                    m_findEdit->setFocus();
            }
        });
    }

    // Ctrl+G → 顯示搜尋欄 & 聚焦 Goto
    {
        QShortcut *sc = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_G), this);
        sc->setContext(ctx);
        connect(sc, &QShortcut::activated, this, [this]() {
            if (!m_searchPanel) return;
            m_searchPanel->show();
            positionSearchPanel();
            if (m_gotoEdit) {
                m_gotoEdit->setFocus();
                m_gotoEdit->selectAll();
            }
        });
    }
}

// 地址長度運算 (預設8)
int HexView::addressChars() const {
    qint64 size = m_dataSize;
    int digits = 1;
    while (size > 0x10) {
        size >>= 4;   // 每 4 bit 一個 hex digit
        digits++;
    }
    return qMax(digits, 8); // 最少 8 位，向上成長
}

// 計算並顯示行數
qint64 HexView::visibleLineCount() const
{
    QFontMetrics fm(font());
    int headerHeight = fm.height();
    if (m_lineHeight <= 0) return 1;

    return qMax<qint64>(
        1,
        (viewport()->height() - headerHeight - m_topMargin * 2) / m_lineHeight
        );
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
    QFontMetrics fm(font());
    int headerHeight = fm.height();

    int totalLines = 0;
    qint64 byteCount = effectiveSize();
    if (m_chunks && byteCount > 0 && m_bytesPerLine > 0) {
        totalLines = (byteCount + m_bytesPerLine - 1) / m_bytesPerLine;
    }

    int linesPerPage = 1;
    if (m_lineHeight > 0) {
        linesPerPage = qMax(1, (viewport()->height() - headerHeight - m_topMargin * 2) / m_lineHeight);
    }

    qint64 res = scrollResolution();
    QScrollBar *v = verticalScrollBar();
    // v->setRange(0, res);
    qint64 maxFirstLine = qMax<qint64>(0, totalLines - visibleLineCount());
    v->setRange(0, maxFirstLine);
    v->setSingleStep(1);
    v->setPageStep(visibleLineCount());

    if (res == totalLines) {
        // 小檔：一頁 = 可見行數
        v->setPageStep(linesPerPage);
        v->setSingleStep(1);
    } else {
        // 大檔：比例模式
        // qint64 page = double(linesPerPage) / double(totalLines * res);
        int page = int(double(linesPerPage) / double(totalLines) * double(res));
        v->setPageStep(qMax(1, page));
        v->setSingleStep(qMax(1, page / 10));
    }
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

void HexView::loadDevice(QIODevice *dev)
{
    delete m_chunks;
    m_chunks = new ChunksLite(dev);

    m_overlay.reset(m_chunks->size());   // ⭐ 新增
    m_dataSize = m_chunks->size();       // base size 仍可留著做顯示或 debug

    m_cursorOffset = 0;
    emit cursorChanged(m_cursorOffset);
    emit dataSizeChanged(effectiveSize());
    emit modifiedChanged(false);
    verticalScrollBar()->setValue(0);

    invalidateAllLines();
    updateScrollBars();
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
    qint64 byteCount = effectiveSize();

    // 地址欄
    QString addr = QString("%1")
                       .arg(base + m_baseOffset, addressChars(), 16, QLatin1Char('0'))
                       .toUpper();
    p.setPen(QColor(160, 160, 160));
    p.drawText(m_leftMargin, y, addr);

    // 畫 HEX + ASCII
    QByteArray lines = m_overlay.read(base, m_bytesPerLine, m_chunks);
    for (int col = 0; col < m_bytesPerLine; ++col) {
        qint64 off = base + col;
        if (off >= byteCount)
            break;

        if (col >= lines.size())
            break;

        if (col < lines.size()) {
            unsigned char byte = static_cast<unsigned char>(lines.at(col));

            int hx = m_hexStartX   + col * m_hexCellWidth;
            int ax = m_asciiStartX + col * m_charWidth;

            QRect hexRect(hx, 0, m_hexCellWidth, m_lineHeight);
            QRect asciiRect(ax, 0, m_charWidth, m_lineHeight);

            bool hasSel = (m_selStart >= 0 && m_selEnd > m_selStart) ||
                          !m_extraSelections.isEmpty();

            bool inSelection = byteInAnySelection(off);

            // 如果有選取 → 不畫游標
            // bool isCursor = (!hasSel && m_showCursor && off == m_cursorOffset);
            bool isCursor = (!hasSel && m_showCursor && off == m_cursorOffset);
            bool halfCursor = isCursor && (lastClickArea == Area::Hex) && !m_hexHighNibble;


            // 紅色錯誤閃爍：編輯錯誤用（Hex 輸入錯字）
            if (m_editFlashCounter > 0 && off == m_cursorOffset) {
                p.fillRect(hexRect, QColor(255, 80, 80, 160));
                p.fillRect(asciiRect, QColor(255, 80, 80, 160));
                p.setPen(Qt::white);
            }
            // 黃色搜尋閃爍：找到的區塊（整個 selection 範圍）
            else if (m_searchFlashCounter > 0 && inSelection) {
                p.fillRect(hexRect, QColor(255, 200, 0, 160));
                p.fillRect(asciiRect, QColor(255, 200, 0, 160));
                p.setPen(Qt::black);
            }
            // 選取
            else if (inSelection) {
                p.fillRect(hexRect, QColor(100, 130, 200));
                p.fillRect(asciiRect, QColor(100, 130, 200));
                p.setPen(Qt::white);
            }
            // 游標
            else if (isCursor) {
                p.fillRect(hexRect, QColor(70, 100, 160));
                p.fillRect(asciiRect, QColor(70, 100, 160));
                p.setPen(Qt::white);
            }
            else {
                p.setPen(QColor(230,230,230));
            }

            p.drawText(hexRect,   Qt::AlignHCenter  | Qt::AlignVCenter, m_hexCache[byte]);
            p.drawText(asciiRect, Qt::AlignHCenter  | Qt::AlignVCenter, m_asciiCache[byte]);
        }
    }

    return img;
}

void HexView::paintEvent(QPaintEvent *event)
{
    Q_UNUSED(event);

    QPainter p(viewport());
    QRect vpRect = viewport()->rect();
    p.fillRect(vpRect, QColor(0x1e, 0x1e, 0x1e));

    // === 計算 header 高度，畫 00 01 02 ... 0F ===
    QFontMetrics fm(font());
    int headerHeight = fm.height();

    // 畫上方 header
    p.setPen(QColor(180, 180, 180));
    for (int col = 0; col < m_bytesPerLine; ++col) {
        QString label = QString("%1")
        .arg(col, 2, 16, QLatin1Char('0'))
            .toUpper();
        int hx = m_hexStartX + col * m_hexCellWidth;
        QRect rect(hx, 0, m_hexCellWidth, headerHeight);
        p.drawText(rect, Qt::AlignHCenter | Qt::AlignVCenter, label);
    }

    qint64 byteCount = effectiveSize();

    if (!m_chunks || byteCount <= 0 || m_lineHeight <= 0 || m_bytesPerLine <= 0)
        return;

    // int vpos = verticalScrollBar()->value();
    qint64 totalLines   = (byteCount + m_bytesPerLine - 1) / m_bytesPerLine;
    qint64 vpos = lineFromScroll();

    qint64 linesPerPage = qMax(1, (viewport()->height() - headerHeight - m_topMargin * 2) / m_lineHeight);
    qint64 lastLine     = qMin(vpos + visibleLineCount(), totalLines);

    // === 把每一行畫到 header 底下 ===
    qint64 baseY = headerHeight + m_topMargin;

    for (int line = vpos; line < lastLine; ++line) {
        int y = baseY + (line - vpos) * m_lineHeight;
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

    positionSearchPanel();   // ⭐ 讓搜尋面板跟著 viewport 位置

    viewport()->update();

    positionInterpretPanel();
}

void HexView::wheelEvent(QWheelEvent *event)
{
    int delta = event->angleDelta().y();
    if (delta == 0) {
        event->ignore();
        return;
    }

    QScrollBar *v = verticalScrollBar();
    if (!v) {
        event->ignore();
        return;
    }

    // 每一個 notch = 1 行
    int steps = delta / 120;
    if (steps == 0)
        steps = (delta > 0) ? 1 : -1;

    int newValue = v->value() - steps;
    newValue = qBound(v->minimum(), newValue, v->maximum());

    v->setValue(newValue);

    event->accept();
    viewport()->update();
}

bool HexView::eventFilter(QObject *obj, QEvent *ev)
{
    if (obj == m_searchPanel) {
        if (ev->type() == QEvent::MouseButtonPress) {
            auto *e = static_cast<QMouseEvent*>(ev);
            if (e->button() == Qt::LeftButton) {
                m_dragSearchPanel = true;
                m_dragOffset = e->pos();
                return true;
            }
        }
        else if (ev->type() == QEvent::MouseMove && m_dragSearchPanel) {
            auto *e = static_cast<QMouseEvent*>(ev);
            m_searchPanel->move(
                m_searchPanel->pos() + e->pos() - m_dragOffset
                );
            return true;
        }
        else if (ev->type() == QEvent::MouseButtonRelease) {
            m_dragSearchPanel = false;
            return true;
        }
    }
    if (obj == m_interpretPanel) {
        if (ev->type() == QEvent::MouseButtonPress) {
            auto *e = static_cast<QMouseEvent*>(ev);
            if (e->button() == Qt::LeftButton) {
                m_dragInterpretPanel = true;
                m_dragInterpretOffset = e->pos();
                return true;
            }
        }
        else if (ev->type() == QEvent::MouseMove && m_dragInterpretPanel) {
            auto *e = static_cast<QMouseEvent*>(ev);
            m_interpretPanel->move(
                m_interpretPanel->pos() + e->pos() - m_dragInterpretOffset
                );
            return true;
        }
        else if (ev->type() == QEvent::MouseButtonRelease) {
            m_dragInterpretPanel = false;
            return true;
        }
    }
    return QAbstractScrollArea::eventFilter(obj, ev);
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
    qint64 byteCount = effectiveSize();
    if (!m_chunks || byteCount <= 0)
        return;

    qint64 line = offset / m_bytesPerLine;
    qint64 first = lineFromScroll();
    qint64 page  = visibleLineCount();

    if (line < first)
        scrollToLine(line);
    else if (line >= first + page)
        scrollToLine(line - page + 1);
}

qint64 HexView::lineFromScroll() const
{
    return verticalScrollBar()->value();
}

void HexView::scrollToLine(qint64 line)
{
    verticalScrollBar()->setValue(line);
}

void HexView::moveCursorRelative(qint64 deltaBytes)
{
    qint64 byteCount = effectiveSize();

    m_showCursor = true;
    if (!(QGuiApplication::keyboardModifiers() & Qt::ShiftModifier)) {
        clearSelectionRange();
        m_extraSelections.clear();
    }

    if (!m_chunks || byteCount <= 0)
        return;

    qint64 newOff = m_cursorOffset + deltaBytes;
    if (newOff < 0) newOff = 0;
    if (newOff >= byteCount) newOff = byteCount - 1;

    if (newOff == m_cursorOffset)
        return;

    m_cursorOffset = newOff;
    ensureVisible(m_cursorOffset);
    emit cursorChanged(m_cursorOffset);
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
    qint64 byteCount = effectiveSize();
    if (!m_chunks || byteCount <= 0)
        return;

    qint64 line = m_cursorOffset / m_bytesPerLine;
    qint64 newOff = line * m_bytesPerLine;
    if (newOff >= byteCount)
        newOff = byteCount - 1;

    moveCursorRelative(newOff - m_cursorOffset);
}

void HexView::moveCursorToLineEnd()
{
    qint64 byteCount = effectiveSize();
    if (!m_chunks || byteCount <= 0)
        return;

    qint64 line = m_cursorOffset / m_bytesPerLine;
    qint64 newOff = line * m_bytesPerLine + (m_bytesPerLine - 1);
    if (newOff >= byteCount)
        newOff = byteCount - 1;

    moveCursorRelative(newOff - m_cursorOffset);
}

bool HexView::handleHexEdit(QKeyEvent *event)
{
    if (!m_editable || !m_chunks)
        return false;

    QString t = event->text();
    if (t.isEmpty())
        return false;

    int v = -1;
    QChar c = t.at(0);
    if (c.isDigit()) v = c.unicode() - '0';
    else if (c >= 'a' && c <= 'f') v = c.unicode() - 'a' + 10;
    else if (c >= 'A' && c <= 'F') v = c.unicode() - 'A' + 10;
    if (v < 0) {
        flashEditError();
        return false;
    }

    QByteArray old = m_overlay.read(m_cursorOffset, 1, m_chunks);
    if (old.isEmpty()) return false;

    uchar oldByte = uchar(old[0]);
    uchar newByte;

    if (m_hexHighNibble)
        newByte = (v << 4) | (oldByte & 0x0F);
    else
        newByte = (oldByte & 0xF0) | v;

    pushReplaceByte(m_cursorOffset, oldByte, newByte);
    m_overlay.replace(m_cursorOffset, QByteArray(1, char(newByte)), m_chunks);

    m_hexHighNibble = !m_hexHighNibble;
    if (m_hexHighNibble)
        moveCursorRelative(1);

    emit modifiedChanged(true);

    invalidateAllLines();
    viewport()->update();
    return true;
}

bool HexView::handleAsciiEdit(QKeyEvent *event)
{
    if (!m_editable || !m_chunks)
        return false;

    QString t = event->text();
    if (t.isEmpty())
        return false;

    uchar newByte = uchar(t.at(0).unicode());
    QByteArray old = m_overlay.read(m_cursorOffset, 1, m_chunks);
    if (old.isEmpty()) return false;

    pushReplaceByte(m_cursorOffset, uchar(old[0]), newByte);
    m_overlay.replace(m_cursorOffset, QByteArray(1, char(newByte)), m_chunks);

    moveCursorRelative(1);
    emit modifiedChanged(true);

    invalidateAllLines();
    viewport()->update();
    return true;
}

void HexView::moveCursorToStart() {
    qint64 byteCount = effectiveSize();
    if (!m_chunks || byteCount <= 0) return;
    m_cursorOffset = 0;
    emit cursorChanged(m_cursorOffset);
    clearSelectionRange();
    m_extraSelections.clear();
    ensureVisible(0);
    invalidateAllLines();
    viewport()->update();
}

void HexView::moveCursorToEnd() {
    qint64 byteCount = effectiveSize();
    if (!m_chunks || byteCount <= 0) return;
    m_cursorOffset = byteCount - 1;
    emit cursorChanged(m_cursorOffset);
    clearSelectionRange();
    m_extraSelections.clear();
    ensureVisible(m_cursorOffset);
    invalidateAllLines();
    viewport()->update();
}

bool HexView::isHexString(const QString &s) {
    QString t = s.trimmed();
    t.remove(' ');
    QRegularExpression re("^[0-9A-Fa-f]+$");
    return re.match(t).hasMatch() && (t.size() % 2 == 0);
}

void HexView::flashLineEditError(QLineEdit *edit) {
    if (!edit) return;

    m_lineEditFlashing = edit;
    m_lineEditFlashCount = 6; // 閃 5 次 (紅 -> 白 -> 紅 -> 白 -> 紅 -> 白)
    m_lineEditOriginalStyle = edit->styleSheet();
    m_lineEditFlashTimer->start();
}

void HexView::flashError()
{
    flashEditError();
}

void HexView::flashEditError() {
    m_editFlashCounter = 3;
    m_errorFlashTimer->start();
}

void HexView::flashSearchError() {
    m_searchFlashCounter = 3;
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

    if (event->modifiers() & Qt::ControlModifier) {
        switch (event->key()) {
        case Qt::Key_Z:
            undo();
            event->accept();
            return;
        case Qt::Key_Y:
            redo();
            event->accept();
            return;
        case Qt::Key_C:
            copySelectionToClipboard();
            event->accept();
            return;
        case Qt::Key_V:
            pasteFromClipboard();
            event->accept();
            return;
        case Qt::Key_A:
            selectAll();
            event->accept();
            return;
        default:
            break; // 其他 Ctrl 組合讓後面照常處理
        }
    }

    if (event->key() == Qt::Key_Escape) {
        // ⭐ 1) 若搜尋面板打開 → 先關掉搜尋面板
        if (m_searchPanel && m_searchPanel->isVisible()) {
            m_searchPanel->hide();
            event->accept();
            this->setFocus();
            return;
        }

        // ⭐ 2) 否則才處理「取消選取 / 游標」邏輯
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
        case Qt::Key_Left:      moveCursorRelative(-1); break;
        case Qt::Key_Right:     moveCursorRelative( 1); break;
        case Qt::Key_Up:        moveCursorLineRelative(-1); break;
        case Qt::Key_Down:      moveCursorLineRelative( 1); break;
        case Qt::Key_PageUp:    moveCursorLineRelative(-visibleLineCount()); break;
        case Qt::Key_PageDown:  moveCursorLineRelative(visibleLineCount()); break;
        case Qt::Key_Home:      if (event->modifiers() & Qt::ControlModifier) moveCursorToStart(); else moveCursorToLineStart(); break;
        case Qt::Key_End:       if (event->modifiers() & Qt::ControlModifier) moveCursorToEnd(); else moveCursorToLineEnd(); break;
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
        moveCursorLineRelative(-visibleLineCount());
        return;
    case Qt::Key_PageDown:
        moveCursorLineRelative(visibleLineCount());
        return;
    case Qt::Key_Home:
        if (event->modifiers() & Qt::ControlModifier)
            moveCursorToStart();
        else
            moveCursorToLineStart();
        return;
    case Qt::Key_End:
        if (event->modifiers() & Qt::ControlModifier)
            moveCursorToEnd();
        else
            moveCursorToLineEnd();
        return;
    case Qt::Key_Return:
    case Qt::Key_Enter:
        event->ignore();
        return;
    case Qt::Key_Insert:
        if (!m_editable)
            return;
        {
            // 在目前游標位置插入 1 byte（預設 0x00）
            qint64 byteCount = effectiveSize();
            qint64 pos = m_cursorOffset;
            if (pos < 0) pos = 0;
            if (pos > byteCount) pos = byteCount;

            QByteArray newData(1, 0x00);
            m_overlay.insert(pos, newData);
            pushInsertBytes(pos, newData);

            // Undo：這裡可以視為「old = 無，new = 0」
            // 若你未來想完整 undo insert，可另外做 EditType
            updateScrollBars();

            m_cursorOffset = pos;
            emit cursorChanged(m_cursorOffset);
            emit dataSizeChanged(effectiveSize());
            emit modifiedChanged(true);
            clearSelectionRange();
            m_extraSelections.clear();

            invalidateAllLines();
            viewport()->update();
        }
        return;
    case Qt::Key_Backspace:
        if (hasSelection() || !m_extraSelections.isEmpty()) {
            deleteRanges(allSelectionsNormalized());
            return;
        } else {
            if (m_cursorOffset > 0) {
                qint64 delPos = m_cursorOffset - 1;
                deleteRanges({ { delPos, delPos + 1 } });

                emit dataSizeChanged(effectiveSize());

                m_cursorOffset = delPos;
                clampCursorToValidRange();
                ensureVisible(m_cursorOffset);

                emit cursorChanged(m_cursorOffset);

                updateScrollBars();
                invalidateAllLines();
                viewport()->update();
            }
            return;
        }
    case Qt::Key_Delete:
        if (hasSelection() || !m_extraSelections.isEmpty()) {
            deleteRanges(allSelectionsNormalized());
            return;
        } else {
            qint64 byteCount = effectiveSize();
            if (m_cursorOffset < byteCount) {
                qint64 delPos = m_cursorOffset;
                deleteRanges({ { delPos, delPos + 1 } });
                updateScrollBars();
                invalidateAllLines();
                viewport()->update();
            }
            return;
        }
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
    emit cursorChanged(m_cursorOffset);
    ensureVisible(m_cursorOffset);
    resetFindState();

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
    m_selAnchor = -1;
    m_dragSelecting = true;
    m_hexHighNibble = true;
    m_selAnchor = m_cursorOffset;
    m_selStart  = m_cursorOffset;
    m_selEnd    = m_cursorOffset + 1;
    m_extraSelections.clear();

    if (m_interpretPanel && m_interpretPanel->isVisible())
        updateInterpretPanel();

    invalidateAllLines();
    viewport()->update();
}

void HexView::mouseMoveEvent(QMouseEvent *event) {
    if (!m_dragSelecting)
        return;

    qint64 off = clickedOffset(event->pos());

    // ⭐ 若滑鼠在 viewport 外（尤其是上方），clickedOffset 會回 -1
    //    我們要做對稱的 auto-scroll：上/下都要能捲
    if (off < 0) {
        QScrollBar *v = verticalScrollBar();
        if (!v) return;

        const QRect vp = viewport()->rect();
        const int margin = 12; // 觸發自動捲動的邊界

        // 往上 auto-scroll
        if (event->pos().y() < vp.top() + margin) {
            v->setValue(qMax(v->minimum(), v->value() - 1));

            // 用「貼在 viewport 上緣」的點來重新取 offset
            QPoint clamped(event->pos().x(), vp.top() + 1);
            off = clickedOffset(clamped);
        }
        // 往下 auto-scroll
        else if (event->pos().y() > vp.bottom() - margin) {
            v->setValue(qMin(v->maximum(), v->value() + 1));

            // 用「貼在 viewport 下緣」的點來重新取 offset
            QPoint clamped(event->pos().x(), vp.bottom() - 1);
            off = clickedOffset(clamped);
        }
        else {
            // 在左右或其他區域外，就先不處理
            return;
        }
    }

    // 重新取得 offset 後，正常更新選取
    if (off >= 0 && off != m_selAnchor) {
        if (off >= m_selAnchor)
            setSelectionRange(m_selAnchor, off + 1);
        else
            setSelectionRange(off, m_selAnchor + 1);

        m_cursorOffset = off;
        ensureVisible(m_cursorOffset);
        viewport()->update();
    }
}

void HexView::mouseReleaseEvent(QMouseEvent *event) {
    if (event->button() == Qt::LeftButton) {
        m_dragSelecting = false;
        m_mouseSelecting = false;
        return;
    }

    QAbstractScrollArea::mouseReleaseEvent(event);
}

qint64 HexView::findBytes(const QByteArray &pattern, qint64 start, bool backwards) {
    qint64 size = effectiveSize();
    if (pattern.isEmpty() || size <= 0)
        return -1;

    if (!backwards) {
        for (qint64 i = start; i + pattern.size() <= size; ++i) {
            if (m_overlay.read(i, pattern.size(), m_chunks) == pattern)
                return i;
        }
    } else {
        for (qint64 i = start; i >= 0; --i) {
            if (m_overlay.read(i, pattern.size(), m_chunks) == pattern)
                return i;
        }
    }
    return -1;
}

void HexView::gotoOffset(qint64 offset) {
    qint64 byteCount = effectiveSize();

    if (!m_chunks || byteCount <= 0)
        return;

    if (offset < 0) offset = 0;
    if (offset >= byteCount) offset = byteCount - 1;

    m_cursorOffset = offset;
    emit cursorChanged(m_cursorOffset);

    // ⭐ 清除所有選取
    clearSelectionRange();
    m_extraSelections.clear();

    // ⭐ 設定選取範圍 = 該 byte
    m_selStart = offset;
    m_selEnd   = offset + 1;
    m_selAnchor = offset;
    lastClickArea = Area::Hex;

    // ⭐ Goto 成功 → 黃色閃爍該 byte
    m_searchFlashCounter = 3;
    m_errorFlashTimer->start();

    ensureVisible(offset);

    invalidateAllLines();
    viewport()->update();
}

qint64 HexView::offsetFromIndex(const QModelIndex &idx) const {
    Q_UNUSED(idx);
    return m_cursorOffset;
}

QModelIndex HexView::currentIndex() const {
    return QModelIndex();
}

qint64 HexView::currentOffset() const {
    return m_cursorOffset;
}

qint64 HexView::getBytesLength() const {
    return m_overlay.size();
}

qint64 HexView::getBaseBytesLength() const {
    return m_dataSize;
}

QByteArray HexView::readBytes(qint64 offset, qint64 len) const {
    return const_cast<OverlayMap&>(m_overlay).read(offset, len, m_chunks);
}

QByteArray HexView::readBaseBytes(qint64 offset, qint64 len) const {
    return m_chunks ? m_chunks->read(offset, len) : QByteArray();
}


bool HexView::saveToFile(const QString &fileName) {
    if (!m_chunks)
        return false;

    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly)) {
        return false;
    }

    const qint64 totalSize = effectiveSize();
    const qint64 BUF = 0x10000; // 64KB，安全又快

    qint64 written = 0;
    while (written < totalSize)
    {
        qint64 len = qMin<qint64>(BUF, totalSize - written);
        QByteArray data = m_overlay.read(written, len, m_chunks);

        if (data.size() != len) {
            file.close();
            return false;
        }

        if (file.write(data) != data.size()) {
            file.close();
            return false;
        }

        written += len;
    }

    file.flush();
    file.close();
    emit modifiedChanged(false);
    return true;
}

void HexView::setFindMode(FindMode mode)
{
    if (m_findMode != mode) {
        m_findMode = mode;
        resetFindState();
    }
}

void HexView::resetFindState()
{
    m_lastPattern.clear();
    m_lastPos = -1;
}

qint64 HexView::findNext(const QString &input)
{
    qint64 pos = doFindInternal(input, false);

    if (pos < 0) {
        flashLineEditError(m_findEdit);
        return -1;
    }

    return pos;
}

qint64 HexView::findPrev(const QString &input)
{
    qint64 pos = doFindInternal(input, true);

    if (pos < 0) {
        flashLineEditError(m_findEdit);
        return -1;
    }

    return pos;
}

qint64 HexView::gotoOffsetFromText(const QString &t)
{
    QString s = t.trimmed();
    qint64 byteCount = effectiveSize();
    if (s.isEmpty() || !m_chunks || byteCount <= 0) {
        flashLineEditError(m_gotoEdit);
        return -1;
    }

    bool ok = false;
    qint64 value = 0;

    if (s.startsWith("0x", Qt::CaseInsensitive)) {
        value = s.mid(2).toLongLong(&ok, 16);
    } else if (s.contains(QRegularExpression("[A-Fa-f]"))) {
        value = s.toLongLong(&ok, 16);
    } else {
        value = s.toLongLong(&ok, 10);
    }

    if (!ok || value < 0 || value >= byteCount) {
        flashLineEditError(m_gotoEdit);
        return -1;
    }

    gotoOffset(value);  // ⭐ 你原本的 API：把 cursor & 視圖移到指定位移
    return value;
}

// ==================== Interpret As Panel ====================
static QString bits8(quint8 v) {
    QString s;
    for (int i = 7; i >= 0; --i) s += ((v >> i) & 1) ? '1' : '0';
    return s;
}

template <typename T>
static bool readLE(const QByteArray& b, int off, T& out)
{
    if (off < 0 || off + (int)sizeof(T) > b.size()) return false;
    T tmp{};
    memcpy(&tmp, b.constData() + off, sizeof(T));
    out = tmp; // 假設 host 為 little-endian（Windows/Linux x86/x64）
    return true;
}

static bool readLE_u24(const QByteArray& b, int off, quint32& out)
{
    if (off < 0 || off + 3 > b.size()) return false;
    out = (quint32)(quint8)b[off]
          | ((quint32)(quint8)b[off+1] << 8)
          | ((quint32)(quint8)b[off+2] << 16);
    return true;
}

static inline quint16 bswap16(quint16 v){
    return (quint16)((v>>8) | (v<<8));
}

static inline quint32 bswap32(quint32 v){
    return ((v & 0x000000FFu) << 24) |
           ((v & 0x0000FF00u) << 8)  |
           ((v & 0x00FF0000u) >> 8)  |
           ((v & 0xFF000000u) >> 24);
}
static inline quint64 bswap64(quint64 v){
    return ((v & 0x00000000000000FFULL) << 56) |
           ((v & 0x000000000000FF00ULL) << 40) |
           ((v & 0x0000000000FF0000ULL) << 24) |
           ((v & 0x00000000FF000000ULL) << 8)  |
           ((v & 0x000000FF00000000ULL) >> 8)  |
           ((v & 0x0000FF0000000000ULL) >> 24) |
           ((v & 0x00FF000000000000ULL) >> 40) |
           ((v & 0xFF00000000000000ULL) >> 56);
}

template <typename T>
static bool readAnyEndian(const QByteArray& b, int off, bool bigEndian, T& out)
{
    if (off < 0 || off + (int)sizeof(T) > b.size()) return false;
    T tmp{};
    memcpy(&tmp, b.constData() + off, sizeof(T));

    // 只處理 2/4/8 bytes 的基本型別（整數/float/double/half）
    if constexpr (sizeof(T) == 2) {
        quint16 v; memcpy(&v, &tmp, 2);
        if (bigEndian) v = bswap16(v);
        memcpy(&out, &v, 2);
        return true;
    } else if constexpr (sizeof(T) == 4) {
        quint32 v; memcpy(&v, &tmp, 4);
        if (bigEndian) v = bswap32(v);
        memcpy(&out, &v, 4);
        return true;
    } else if constexpr (sizeof(T) == 8) {
        quint64 v; memcpy(&v, &tmp, 8);
        if (bigEndian) v = bswap64(v);
        memcpy(&out, &v, 8);
        return true;
    } else {
        out = tmp;
        return true;
    }
}

static bool readAnyEndian_u24(const QByteArray& b, int off, bool bigEndian, quint32& out)
{
    if (off < 0 || off + 3 > b.size()) return false;
    if (!bigEndian) {
        out = (quint32)(quint8)b[off]
              | ((quint32)(quint8)b[off+1] << 8)
              | ((quint32)(quint8)b[off+2] << 16);
    } else {
        out = ((quint32)(quint8)b[off]   << 16)
        | ((quint32)(quint8)b[off+1] << 8)
            | ((quint32)(quint8)b[off+2]);
    }
    return true;
}

static qint32 signExtend24(quint32 u24)
{
    if (u24 & 0x800000) return (qint32)(u24 | 0xFF000000);
    return (qint32)u24;
}

static QByteArray encodeULEB128(quint64 v)
{
    QByteArray out;
    do {
        quint8 b = (quint8)(v & 0x7F);
        v >>= 7;
        if (v) b |= 0x80;
        out.append((char)b);
    } while (v);
    return out;
}

static QByteArray encodeSLEB128(qint64 v)
{
    QByteArray out;
    bool more = true;
    while (more) {
        quint8 b = (quint8)(v & 0x7F);
        bool sign = (b & 0x40) != 0;
        v >>= 7;

        if ((v == 0 && !sign) || (v == -1 && sign))
            more = false;
        else
            b |= 0x80;

        out.append((char)b);
    }
    return out;
}

static bool decodeULEB128(const QByteArray& b, int off, quint64& value, int& used)
{
    value = 0;
    used = 0;
    quint64 shift = 0;
    for (int i = 0; i < 10 && off + i < b.size(); ++i) {
        quint8 byte = (quint8)b[off + i];
        value |= (quint64)(byte & 0x7F) << shift;
        used++;
        if ((byte & 0x80) == 0) return true;
        shift += 7;
    }
    return false;
}

static bool decodeSLEB128(const QByteArray& b, int off, qint64& value, int& used)
{
    value = 0;
    used = 0;
    qint64 shift = 0;
    quint8 byte = 0;
    for (int i = 0; i < 10 && off + i < b.size(); ++i) {
        byte = (quint8)b[off + i];
        value |= (qint64)(byte & 0x7F) << shift;
        used++;
        shift += 7;
        if ((byte & 0x80) == 0) {
            if (shift < 64 && (byte & 0x40))
                value |= -(1LL << shift);
            return true;
        }
    }
    return false;
}

static quint16 floatToHalf(float f)
{
    quint32 x; memcpy(&x, &f, 4);
    quint32 sign = (x >> 31) & 1;
    qint32 exp = (qint32)((x >> 23) & 0xFF) - 127 + 15;
    quint32 mant = x & 0x7FFFFF;

    if (exp <= 0) {
        if (exp < -10) return (quint16)(sign << 15);
        mant |= 0x800000;
        quint32 m = mant >> (1 - exp);
        return (quint16)((sign << 15) | (m >> 13));
    } else if (exp >= 31) {
        return (quint16)((sign << 15) | (0x1F << 10)); // inf
    } else {
        return (quint16)((sign << 15) | ((quint32)exp << 10) | (mant >> 13));
    }
}

static float halfToFloat(quint16 h)
{
    quint32 sign = (h >> 15) & 1;
    quint32 exp  = (h >> 10) & 0x1F;
    quint32 frac = h & 0x3FF;

    quint32 fsign = sign << 31;
    quint32 fexp;
    quint32 ffrac;

    if (exp == 0) {
        if (frac == 0) {
            fexp = 0; ffrac = 0;
        } else {
            int e = -1;
            quint32 f = frac;
            while ((f & 0x400) == 0) { f <<= 1; e--; }
            f &= 0x3FF;
            fexp = (quint32)(127 - 15 + 1 + e) << 23;
            ffrac = f << 13;
        }
    } else if (exp == 31) {
        fexp = 0xFFu << 23;
        ffrac = frac ? (frac << 13) : 0;
    } else {
        fexp = (quint32)(exp - 15 + 127) << 23;
        ffrac = frac << 13;
    }

    quint32 bits = fsign | fexp | ffrac;
    float out;
    memcpy(&out, &bits, sizeof(out));
    return out;
}

static QString formatGuid(const QByteArray& b, int off)
{
    if (off < 0 || off + 16 > b.size()) return QString();
    quint32 d1 = (quint32)(quint8)b[off] | ((quint32)(quint8)b[off+1] << 8) | ((quint32)(quint8)b[off+2] << 16) | ((quint32)(quint8)b[off+3] << 24);
    quint16 d2 = (quint16)(quint8)b[off+4] | ((quint16)(quint8)b[off+5] << 8);
    quint16 d3 = (quint16)(quint8)b[off+6] | ((quint16)(quint8)b[off+7] << 8);
    const quint8* d4 = (const quint8*)b.constData() + off + 8;

    return QString("%1-%2-%3-%4%5-%6%7%8%9%10%11")
        .arg(d1, 8, 16, QLatin1Char('0'))
        .arg(d2, 4, 16, QLatin1Char('0'))
        .arg(d3, 4, 16, QLatin1Char('0'))
        .arg(d4[0], 2, 16, QLatin1Char('0'))
        .arg(d4[1], 2, 16, QLatin1Char('0'))
        .arg(d4[2], 2, 16, QLatin1Char('0'))
        .arg(d4[3], 2, 16, QLatin1Char('0'))
        .arg(d4[4], 2, 16, QLatin1Char('0'))
        .arg(d4[5], 2, 16, QLatin1Char('0'))
        .arg(d4[6], 2, 16, QLatin1Char('0'))
        .arg(d4[7], 2, 16, QLatin1Char('0'))
        .toUpper();
}

#if HEXVIEW_HAVE_CAPSTONE
static QString disasmX86(const QByteArray& b, cs_mode mode, int maxInsns, int maxBytes, int& usedBytesOut)
#else
static QString disasmX86(const QByteArray& b, void *mode, int maxInsns, int maxBytes, int& usedBytesOut)
#endif
{
    usedBytesOut = 0;

#if !HEXVIEW_HAVE_CAPSTONE
    Q_UNUSED(b); Q_UNUSED(mode); Q_UNUSED(maxInsns); Q_UNUSED(maxBytes);
    return QStringLiteral("(capstone not available)");
#else
    csh handle;
    if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK)
        return QStringLiteral("(capstone init failed)");

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

    const int nBytes = qMin(maxBytes, b.size());
    if (nBytes <= 0) {
        cs_close(&handle);
        return QStringLiteral("(need bytes)");
    }

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(handle,
                             (const uint8_t*)b.constData(),
                             (size_t)nBytes,
                             0,               // address
                             (size_t)maxInsns,
                             &insn);

    if (count == 0) {
        cs_close(&handle);
        return QStringLiteral("(no instruction)");
    }

    QString out;
    uint64_t endAddr = 0;
    for (size_t i = 0; i < count; ++i) {
        const cs_insn& ci = insn[i];
        endAddr = ci.address + ci.size;

        // bytes
        QString bytes;
        for (uint8_t k = 0; k < ci.size; ++k)
            bytes += QString("%1 ").arg(ci.bytes[k], 2, 16, QLatin1Char('0')).toUpper();
        bytes = bytes.trimmed();

        // ⭐ 正確的 Qt 字串組法（不混用 printf）
        // out += QString("%1  %2 %3\n")
        out += QString("%1 %2\n")
                   // .arg(QString::number((quint64)ci.address, 16).rightJustified(4, '0').toUpper())
                   // .arg(bytes.leftJustified(23, ' '))   // 對齊用 Qt 自己的 API
                   .arg(ci.mnemonic)
                   .arg(ci.op_str);
    }

    usedBytesOut = (int)endAddr;
    cs_free(insn, count);
    cs_close(&handle);

    return out.trimmed();
#endif
}

void HexView::createInterpretPanel()
{
    m_interpretPanel = new QWidget(this);
    m_interpretPanel->setAutoFillBackground(true);

    QPalette pal = m_interpretPanel->palette();
    pal.setColor(QPalette::Window, QColor(32, 32, 32, 235));
    m_interpretPanel->setPalette(pal);
    m_interpretPanel->setAttribute(Qt::WA_StyledBackground, true);
    m_interpretPanel->setStyleSheet(
        "QWidget { border: 1px solid #666666; border-radius: 6px; }"
        "QToolButton { background:#333333; color:#ffffff; border:1px solid #555555; padding:0 6px; }"
        "QToolButton:hover { background:#444444; }"
        "QTableWidget { background:#111317; color:#dfe3ea; border:1px solid #343a46; border-radius:6px; }"
        "QHeaderView::section { background:#2b2f3a; color:#eaeaea; border:0px; padding:4px; font-weight:bold; }"
        "QScrollBar:vertical { background: #1f1f1f; width: 10px; }"
        "QScrollBar::handle:vertical { background: #3a3f4b; border-radius: 4px; }"
        "QScrollBar::handle:vertical:hover { background: #505357; }"
        "QScrollBar:horizontal { background: #1f1f1f; width: 10px; }"
        "QScrollBar::handle:horizontal { background: #3a3f4b; border-radius: 4px; }"
        "QScrollBar::handle:horizontal:hover { background: #505357; }"
        );

    m_interpretPanel->installEventFilter(this);

    auto* root = new QVBoxLayout(m_interpretPanel);
    root->setContentsMargins(8, 8, 8, 8);
    root->setSpacing(6);

    auto* titleRow = new QHBoxLayout();
    titleRow->setContentsMargins(0,0,0,0);

    auto* lb = new QLabel(tr("Interpret As"), m_interpretPanel);
    lb->setStyleSheet("QLabel{ color:#e8e8e8; font-weight:600; }");

    m_btnInterpretClose = new QToolButton(m_interpretPanel);
    m_btnInterpretClose->setText("×");
    m_btnInterpretClose->setToolTip(tr("Close"));

    titleRow->addWidget(lb);

    // Endian Combo
    m_endianCombo = new QComboBox(m_interpretPanel);
    m_endianCombo->addItem("LE");
    m_endianCombo->addItem("BE");
    m_endianCombo->setCurrentIndex(0);
    m_endianCombo->setFixedHeight(24);
    m_endianCombo->setStyleSheet(
        "QComboBox { background:#2b2f3a; color:#eaeaea; border:1px solid #3a3f4b; border-radius:6px; padding:2px 8px; }"
        "QComboBox QAbstractItemView { background:#2b2f3a; color:#eaeaea; selection-background-color:#3b4150; }"
        );

    titleRow->addStretch(1);
    titleRow->addWidget(new QLabel(tr("Endian:"), m_interpretPanel));
    titleRow->addWidget(m_endianCombo);
    titleRow->addWidget(m_btnInterpretClose);

    // 切換就更新
    connect(m_endianCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int idx){
        m_interpretBigEndian = (idx == 1);
        if (m_interpretPanel && m_interpretPanel->isVisible())
            updateInterpretPanel();
    });

    m_interpretTable = new QTableWidget(m_interpretPanel);
    m_interpretTable->setColumnCount(2);
    m_interpretTable->setHorizontalHeaderLabels({tr("Type"), tr("Value")});
    m_interpretTable->verticalHeader()->setVisible(false);
    m_interpretTable->setShowGrid(false);
    m_interpretTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_interpretTable->setSelectionMode(QAbstractItemView::NoSelection);
    m_interpretTable->setFocusPolicy(Qt::NoFocus);
    m_interpretTable->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_interpretTable->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_interpretTable->horizontalHeader()->setStretchLastSection(false);
    m_interpretTable->setRowCount(30);
    m_interpretTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_interpretTable, &QTableWidget::customContextMenuRequested,
            this, [this](const QPoint& pos)
            {
                QTableWidgetItem* it = m_interpretTable->itemAt(pos);
                if (!it) return;

                QMenu menu(m_interpretTable);

                QAction* actEdit = nullptr;
                if (it->column() == 1 && (it->flags() & Qt::ItemIsEditable))
                    actEdit = menu.addAction(tr("Edit"));

                QAction* actCopy = menu.addAction(tr("Copy"));

                QAction* chosen = menu.exec(m_interpretTable->viewport()->mapToGlobal(pos));
                if (chosen == actEdit) {
                    m_interpretTable->setCurrentItem(it);
                    m_interpretTable->editItem(it);
                }
                else if (chosen == actCopy) {
                    QString s = interpretRawText(it);
                    QGuiApplication::clipboard()->setText(s);
                }
            });
    // Ctrl+C Copy raw
    new QShortcut(Qt::CTRL | Qt::Key_C, m_interpretTable, [this] {
        auto items = m_interpretTable->selectedItems();
        if (items.isEmpty()) return;
        QGuiApplication::clipboard()->setText(interpretRawText(items.first()));
    });
    m_interpretTable->setEditTriggers(QAbstractItemView::DoubleClicked | QAbstractItemView::EditKeyPressed);

    auto* del = new InterpretValueDelegate(m_interpretTable);
    m_interpretTable->setItemDelegateForColumn(1, del);
    connect(del, &QAbstractItemDelegate::commitData,
            this, [this, del](QWidget*)
            {
                QTableWidgetItem* it = m_interpretTable->currentItem();
                if (!it || it->column() != 1) return;
                if (!(it->flags() & Qt::ItemIsEditable)) return;

                m_interpretUpdating = false;
                onInterpretItemEdited(it);
            });

    auto *hh = m_interpretTable->horizontalHeader();
    hh->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    hh->setSectionResizeMode(1, QHeaderView::Stretch);
    hh->setStretchLastSection(false);

    root->addLayout(titleRow);
    root->addWidget(m_interpretTable, 1);

    m_interpretPanel->resize(520, 420);
    m_interpretPanel->hide();

    connect(m_btnInterpretClose, &QToolButton::clicked, this, [this]() {
        if (m_interpretPanel) m_interpretPanel->hide();
    });

    connect(this, &HexView::cursorChanged, this, [this](qint64) {
        if (m_interpretPanel && m_interpretPanel->isVisible())
            updateInterpretPanel();
    });
}

void HexView::positionInterpretPanel()
{
    if (!m_interpretPanel) return;

    QRect vpRect = viewport()->geometry();
    QPoint topLeft = QPoint(vpRect.right() - m_interpretPanel->width(), vpRect.top());
    m_interpretPanel->move(topLeft);
    m_interpretPanel->resize(520, vpRect.bottom() - vpRect.top());
    m_interpretPanel->raise();
}

void HexView::setupInterpretShortcuts()
{
    auto ctx = Qt::WidgetWithChildrenShortcut;

    QShortcut *sc = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_D), this);
    sc->setContext(ctx);
    connect(sc, &QShortcut::activated, this, [this]() {
        if (!m_interpretPanel) return;
        if (m_interpretPanel->isVisible()) {
            m_interpretPanel->hide();
            return;
        }
        m_interpretPanel->show();
        positionInterpretPanel();
        updateInterpretPanel();
    });
}

QByteArray HexView::bytesForInterpret(int maxLen) const
{
    if (!m_chunks || maxLen <= 0) return {};

    qint64 base = hasSelection() ? m_selStart : m_cursorOffset;
    if (base < 0) base = 0;

    qint64 sz = effectiveSize();
    if (sz <= 0 || base >= sz) return {};

    qint64 can = qMin<qint64>(maxLen, sz - base);
    return readBytes(base, can);
}

void HexView::updateInterpretPanel()
{
    if (!m_interpretTable) return;

    QSignalBlocker blocker(m_interpretTable); // 完全阻止 itemChanged
    m_interpretUpdating = true;

    auto setRow = [this](int r, const QString& type, const QString& displayValue, const QString& rawValue, int usedBytes) {
        auto* it0 = m_interpretTable->item(r, 0);
        if (!it0) { it0 = new QTableWidgetItem(); m_interpretTable->setItem(r, 0, it0); }
        it0->setText(type);
        it0->setFlags(it0->flags() & ~Qt::ItemIsEditable);

        auto* it1 = m_interpretTable->item(r, 1);
        if (!it1) { it1 = new QTableWidgetItem(); m_interpretTable->setItem(r, 1, it1); }
        // ✅ raw：給 Copy / Edit 用（永遠不帶 "(xx bytes)" 也不帶多餘空白）
        it1->setData(Qt::UserRole, rawValue.trimmed());
        it1->setData(Qt::UserRole + 1, usedBytes);
        it1->setText(displayValue);

        auto isEditableRow = [&](int rr)->bool {
            switch (rr) {
            case 27:
            case 28:
            case 29:
                return false;
            default:
                return true;
            }
        };

        Qt::ItemFlags f = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
        if (isEditableRow(r))
            f |= Qt::ItemIsEditable;
        it1->setFlags(f);
    };

    QByteArray b = bytesForInterpret(64);
    const bool BE = m_interpretBigEndian;
    auto need = [&](int n) { return b.size() >= n; };

    setRow(0,  tr("Binary (8-bit)"), need(1) ? QString("%1  (8 bits)").arg(bits8((quint8)b[0])) : tr("(need 1 byte)"), need(1) ? bits8((quint8)b[0]) : tr(""), 1);
    setRow(1,  tr("Int8"),           need(1) ? QString("%1  (1 byte)").arg((qint8)(quint8)b[0]) : tr("(need 1 byte)"), need(1) ? QString("%1").arg((qint8)(quint8)b[0]) : tr(""), 1);
    setRow(2,  tr("UInt8"),          need(1) ? QString("%1  (1 byte)").arg((quint8)b[0]) : tr("(need 1 byte)"),        need(1) ? QString("%1").arg((quint8)b[0]) : tr(""), 1);

    qint16 i16{}; quint16 u16{};
    bool ndi16 = readAnyEndian(b,0,BE,i16);
    bool ndu16 = readAnyEndian(b,0,BE,u16);
    setRow(3,  tr("Int16"),  ndi16 ? QString("%1  (2 bytes)").arg(i16) : tr("(need 2 bytes)"), ndi16 ? QString("%1").arg(i16) : tr(""), 2);
    setRow(4,  tr("UInt16"), ndu16 ? QString("%1  (2 bytes)").arg(u16) : tr("(need 2 bytes)"), ndu16 ? QString("%1").arg(u16) : tr(""), 2);
    
    quint32 u24{};
    if (readAnyEndian_u24(b,0,BE,u24)) {
        setRow(5, tr("Int24"),  QString("%1  (3 bytes)").arg(signExtend24(u24)),    QString("%1").arg(signExtend24(u24)), 3);
        setRow(6, tr("UInt24"), QString("%1  (3 bytes)").arg(u24),                  QString("%1").arg(u24), 3);
    } else {
        setRow(5, tr("Int24"),  tr("(need 3 bytes)"), tr(""), 3);
        setRow(6, tr("UInt24"), tr("(need 3 bytes)"), tr(""), 3);
    }

    qint32 i32{}; quint32 u32{};
    bool ndi32 = readAnyEndian(b,0,BE,i32);
    bool ndu32 = readAnyEndian(b,0,BE,u32);
    setRow(7,  tr("Int32"),  ndi32 ? QString("%1  (4 bytes)").arg(i32) : tr("(need 4 bytes)"), ndi32 ? QString("%1").arg(i32) : tr(""), 4);
    setRow(8,  tr("UInt32"), ndu32 ? QString("%1  (4 bytes)").arg(u32) : tr("(need 4 bytes)"), ndu32 ? QString("%1").arg(u32) : tr(""), 4);

    qint64 i64{}; quint64 u64{};
    bool ndi64 = readAnyEndian(b,0,BE,i64);
    bool ndu64 = readAnyEndian(b,0,BE,u64);
    setRow(9,  tr("Int64"),  ndi64 ? QString("%1  (8 bytes)").arg(i64) : tr("(need 8 bytes)"), ndi64 ? QString("%1").arg(i64) : tr(""), 8);
    setRow(10, tr("UInt64"), ndu64 ? QString("%1  (8 bytes)").arg(u64) : tr("(need 8 bytes)"), ndu64 ? QString("%1").arg(u64) : tr(""), 8);

    { qint64 lv=0; int used=0; bool ok = decodeSLEB128(b,0,lv,used);
        setRow(11, tr("SLEB128"), ok ? (QString::number(lv) + QString("  (%1 bytes)").arg(used)) : tr("(need valid SLEB128)"), ok ? QString::number(lv) : tr(""), used); }
    { quint64 uv=0; int used=0; bool ok = decodeULEB128(b,0,uv,used);
        setRow(12, tr("ULEB128"), ok ? (QString::number(uv) + QString("  (%1 bytes)").arg(used)) : tr("(need valid ULEB128)"), ok ? QString::number(uv) : tr(""), used); }

    if (need(1)) {
        quint8 ch = (quint8)b[0];
        QChar qc = (ch >= 0x20 && ch < 0x7F) ? QChar(ch) : QChar();
        setRow(13, tr("AnsiChar / ASCII"), QString("'%1'  (0x%2)  (1 byte)").arg(qc).arg(ch,2,16,QLatin1Char('0')), QString("%1").arg(qc), 1);
    } else setRow(13, tr("AnsiChar / ASCII"), tr("(need 1 byte)"), tr(""), 1);

    quint16 wc{};
    if (readAnyEndian(b,0,BE,wc)) {
        QChar qc(wc);
        setRow(14, tr("WideChar / char16_t"), QString("U+%1  '%2'  (2 bytes)").arg(wc,4,16,QLatin1Char('0')).arg(qc), QString("%1").arg(qc), 2);
    } else setRow(14, tr("WideChar / char16_t"), tr("(need 2 bytes)"), tr(""), 2);

    // UTF-8 code point
    if (!need(1)) {
        setRow(15, tr("UTF-8 code point"), tr("(need 1+ bytes)"), tr(""), 0);
    } else {
        const quint8 c0 = (quint8)b[0];
        int needBytes = 1;
        quint32 cp = 0;
        bool ok = true;
        if ((c0 & 0x80) == 0) { cp = c0; needBytes = 1; }
        else if ((c0 & 0xE0) == 0xC0) { needBytes = 2; cp = c0 & 0x1F; }
        else if ((c0 & 0xF0) == 0xE0) { needBytes = 3; cp = c0 & 0x0F; }
        else if ((c0 & 0xF8) == 0xF0) { needBytes = 4; cp = c0 & 0x07; }
        else ok = false;

        if (ok && b.size() >= needBytes) {
            for (int i=1;i<needBytes;i++) {
                quint8 cx = (quint8)b[i];
                if ((cx & 0xC0) != 0x80) { ok = false; break; }
                cp = (cp << 6) | (cx & 0x3F);
            }
        } else ok = false;

        if (ok) {
            QString s = QString::fromUcs4(&cp, 1);
            setRow(15, tr("UTF-8 code point"), QString("U+%1  '%2'  (%3 bytes)").arg(cp,0,16).arg(s).arg(needBytes), QString("%1").arg(s), needBytes);
        } else {
            setRow(15, tr("UTF-8 code point"), tr("(invalid UTF-8)"), tr(""), 0);
        }
    }

    quint16 h16{};
    if (readAnyEndian(b,0,BE,h16))
        setRow(16, tr("Half (Float16)"), QString("%1  (2 bytes)").arg(QString::number(halfToFloat(h16), 'g', 10)), QString("%1").arg(QString::number(halfToFloat(h16), 'g', 10)), 2);
    else
        setRow(16, tr("Half (Float16)"), tr("(need 2 bytes)"), tr(""), 2);

    float f32{};
    bool ndf32 = readAnyEndian(b,0,BE,f32);
    setRow(17, tr("Single (Float32)"), ndf32 ? QString("%1  (4 bytes)").arg(QString::number(f32,'g',10)) : tr("(need 4 bytes)"), ndf32 ? QString("%1").arg(QString::number(f32,'g',10)) : tr(""), 4);

    double f64d{};
    bool ndf64 = readAnyEndian(b,0,BE,f64d);
    setRow(18, tr("Double (Float64)"), ndf64 ? QString("%1  (8 bytes)").arg(QString::number(f64d,'g',16)) : tr("(need 8 bytes)"), ndf64 ? QString("%1").arg(QString::number(f64d,'g',10)) : tr(""), 8);

    // OLETIME
    double ole{};
    if (readAnyEndian(b,0,BE,ole)) {
        QDateTime base(QDate(1899,12,30), QTime(0,0,0), Qt::UTC);
        qint64 secs = (qint64)llround(ole * 86400.0);
        QDateTime dt = base.addSecs(secs);
        setRow(19, tr("OLETIME"), dt.isValid() ? (dt.toString(Qt::ISODate) + "  (8 bytes)") : tr("(invalid)"), dt.isValid() ? (dt.toString(Qt::ISODate)) : tr(""), 8);
    } else setRow(19, tr("OLETIME"), tr("(need 8 bytes)"), tr(""), 8);

    // FILETIME
    if (readAnyEndian(b,0,BE,u64)) {
        const quint64 HUNDRED_NANO_PER_SEC = 10000000ULL;
        quint64 secs = u64 / HUNDRED_NANO_PER_SEC;
        QDateTime base(QDate(1601,1,1), QTime(0,0,0), Qt::UTC);
        QDateTime dt = base.addSecs((qint64)secs);
        setRow(20, tr("FILETIME"), dt.isValid() ? (dt.toString(Qt::ISODate) + "  (8 bytes)") : tr("(invalid)"), dt.isValid() ? (dt.toString(Qt::ISODate)) : tr(""), 8);
    } else setRow(20, tr("FILETIME"), tr("(need 8 bytes)"), tr(""), 8);

    // DOS Date
    quint16 d{};
    if (readAnyEndian(b,0,BE,d)) {
        quint16 d = u16;
        int day = d & 0x1F;
        int mon = (d >> 5) & 0x0F;
        int yr  = ((d >> 9) & 0x7F) + 1980;
        QDate date(yr, mon, day);
        setRow(21, tr("DOS Date"), date.isValid() ? date.toString(Qt::ISODate) + "  (2 bytes)" : tr("(invalid)"), date.isValid() ? date.toString(Qt::ISODate) : tr(""), 2);
    } else setRow(21, tr("DOS Date"), tr("(need 2 bytes)"), tr(""), 2);

    // DOS Time
    quint16 t{};
    if (readAnyEndian(b,0,BE,t)) {
        quint16 t = u16;
        int sec = (t & 0x1F) * 2;
        int min = (t >> 5) & 0x3F;
        int hr  = (t >> 11) & 0x1F;
        QTime time(hr, min, sec);
        setRow(22, tr("DOS Time"), time.isValid() ? time.toString("HH:mm:ss") + "  (2 bytes)" : tr("(invalid)"), time.isValid() ? time.toString("HH:mm:ss") : tr(""), 2);
    } else setRow(22, tr("DOS Time"), tr("(need 2 bytes)"), tr(""), 2);

    // DOS DateTime (time low, date high)
    t = {}, d = {};
    if (readAnyEndian(b,0,BE,t) && readAnyEndian(b,2,BE,d)) {
        int sec = (t & 0x1F) * 2;
        int min = (t >> 5) & 0x3F;
        int hr  = (t >> 11) & 0x1F;
        int day = d & 0x1F;
        int mon = (d >> 5) & 0x0F;
        int yr  = ((d >> 9) & 0x7F) + 1980;
        QDateTime dt(QDate(yr,mon,day), QTime(hr,min,sec), Qt::UTC);
        setRow(23, tr("DOS DateTime"), dt.isValid() ? dt.toString(Qt::ISODate) + "  (4 bytes)" : tr("(invalid)"), dt.isValid() ? dt.toString(Qt::ISODate) : tr(""), 4);
    } else setRow(23, tr("DOS DateTime"), tr("(need 4 bytes)"), tr(""), 4);

    // time_t 32/64
    qint32 time_i32{};
    if (readAnyEndian(b,0,BE,time_i32))
        setRow(24, tr("time_t (32-bit)"), QDateTime::fromSecsSinceEpoch((qint64)time_i32, Qt::UTC).toString(Qt::ISODate) + "  (4 bytes)", QDateTime::fromSecsSinceEpoch((qint64)time_i32, Qt::UTC).toString(Qt::ISODate), 4);
    else
        setRow(24, tr("time_t (32-bit)"), tr("(need 4 bytes)"), tr(""), 4);

    qint64 time_i64{};
    if (readAnyEndian(b,0,BE,time_i64))
        setRow(25, tr("time_t (64-bit)"), QDateTime::fromSecsSinceEpoch(time_i64, Qt::UTC).toString(Qt::ISODate) + "  (8 bytes)", QDateTime::fromSecsSinceEpoch(time_i64, Qt::UTC).toString(Qt::ISODate), 8);
    else
        setRow(25, tr("time_t (64-bit)"), tr("(need 8 bytes)"), tr(""), 8);

    // GUID
    { QString g = formatGuid(b, 0);
        setRow(26, tr("GUID"), g.isEmpty() ? tr("(need 16 bytes)") : g, g.isEmpty() ? tr("") : g, 16); }

    // Disasm placeholder
    QString hx;
    for (int i=0;i<qMin(16,b.size());++i)
        hx += QString("%1 ").arg((quint8)b[i],2,16,QLatin1Char('0')).toUpper();
    hx = hx.trimmed();

#if !HEXVIEW_HAVE_CAPSTONE
    setRow(27, tr("Disasm (x86-16)"), tr("(not implemented) bytes: %1").arg(hx));
    setRow(28, tr("Disasm (x86-32)"), tr("(not implemented) bytes: %1").arg(hx));
    setRow(29, tr("Disasm (x86-64)"), tr("(not implemented) bytes: %1").arg(hx));
#else
    // Disasm (x86) — 用 Capstone，顯示前幾條指令 + 使用了多少 bytes
    {
        int used16=0, used32=0, used64=0;
        QString d16 = disasmX86(b, CS_MODE_16, 1, 32, used16);
        QString d32 = disasmX86(b, CS_MODE_32, 1, 32, used32);
        QString d64 = disasmX86(b, CS_MODE_64, 1, 32, used64);

        setRow(27, tr("Disasm (x86-16)"), d16 + QString("  (%1 bytes)").arg(used16), d16, used16);
        setRow(28, tr("Disasm (x86-32)"), d32 + QString("  (%1 bytes)").arg(used32), d32, used32);
        setRow(29, tr("Disasm (x86-64)"), d64 + QString("  (%1 bytes)").arg(used64), d64, used64);
    }
#endif

    // ⭐ 自動調整 Type 欄位寬度，適配最長文字
    if (m_interpretTable) {
        m_interpretTable->resizeColumnToContents(0);

        // 稍微加一點 padding，避免文字貼邊
        int w = m_interpretTable->columnWidth(0);
        m_interpretTable->setColumnWidth(0, w + 12);
    }

    m_interpretUpdating = false;
}

void HexView::interpretApplyBytes(qint64 pos, int oldLen, const QByteArray& newBytes)
{
    if (!m_editable || !m_chunks) return;
    if (pos < 0) return;
    if (oldLen < 0) oldLen = 0;

    qint64 sz = effectiveSize();
    if (sz <= 0 || pos > sz) return;

    // 讀舊資料（oldLen 可能超出尾端）
    int canOld = (int)qMin<qint64>(oldLen, sz - pos);
    QByteArray oldData = (canOld > 0) ? m_overlay.read(pos, canOld, m_chunks) : QByteArray();

    // 1) 若需要先刪掉多出部分
    if (canOld > newBytes.size()) {
        int delLen = canOld - newBytes.size();
        auto pieces = m_overlay.eraseAndReturnPieces(pos + newBytes.size(), delLen);
        pushDeletePieces(pos + newBytes.size(), pieces, delLen);
    }

    // 2) Replace 前 minLen
    int minLen = qMin(oldData.size(), newBytes.size());
    if (minLen > 0) {
        QByteArray oldPart = oldData.left(minLen);
        QByteArray newPart = newBytes.left(minLen);
        pushEdit(Edit::Type::Replace, pos, oldPart, newPart);
        m_overlay.replace(pos, newPart, m_chunks);
    }

    // 3) 若需要插入額外 bytes
    if (newBytes.size() > oldData.size()) {
        QByteArray ins = newBytes.mid(oldData.size());
        m_overlay.insert(pos + oldData.size(), ins);
        pushInsertBytes(pos + oldData.size(), ins);
        updateScrollBars();
        emit dataSizeChanged(effectiveSize());
    }

    emit modifiedChanged(true);

    // 更新游標/選取/畫面
    clearSelectionRange();
    m_extraSelections.clear();
    setSelectionRange(pos, pos + newBytes.size());
    m_cursorOffset = pos;
    clampCursorToValidRange();
    ensureVisible(m_cursorOffset);
    emit cursorChanged(m_cursorOffset);

    invalidateAllLines();
    viewport()->update();

    if (m_interpretPanel && m_interpretPanel->isVisible())
        updateInterpretPanel();
}

QString HexView::interpretRawText(QTableWidgetItem* it) const
{
    if (!it) return {};
    QString raw = it->data(Qt::UserRole).toString().trimmed();
    if (!raw.isEmpty()) return raw;

    // fallback：如果沒有 raw，就用顯示文字，但也把 "(xxx bytes)" 剪掉
    QString t = it->text().trimmed();
    int p = t.indexOf(" (");
    if (p > 0) t = t.left(p).trimmed();
    return t;
}

void HexView::onInterpretItemEdited(QTableWidgetItem *item) {
    if (m_interpretUpdating) return;
    if (!item) return;
    if (!m_interpretTable) return;

    const QString oldRaw =
        item->data(Qt::UserRole + 100).toString();

    const QString newRaw =
        item->text().trimmed();

    qDebug() << "Old: " << oldRaw << "New: " << newRaw;

    // ⭐ 沒變 → 直接 return，不標記 modified、不寫入
    if (oldRaw == newRaw)
        return;

    const int row = item->row();
    const int col = item->column();
    if (col != 1) return;                 // 只允許改 Value 欄
    if (!m_editable || !m_chunks) return;

    // base offset：有選取就用 selStart，否則用 cursor
    qint64 pos = hasSelection() ? m_selStart : m_cursorOffset;
    const bool BE = m_interpretBigEndian;

    // QString text = interpretRawText(item).trimmed();
    QString text = item->text().trimmed();
    if (text.isEmpty()) return;

    // 0=未知，固定長會直接指定
    int oldLen = item->data(Qt::UserRole + 1).toInt();

    QByteArray bytes;
    bool ok = false;

    auto parseI64 = [&](qint64 &v){ v = text.toLongLong(&ok, 0); return ok; };
    auto parseU64 = [&](quint64 &v){ v = text.toULongLong(&ok, 0); return ok; };

    auto parseInt64 = [&](qint64& out)->bool{
        out = text.toLongLong(&ok, 0);
        return ok;
    };
    auto parseUInt64 = [&](quint64& out)->bool{
        out = text.toULongLong(&ok, 0);
        return ok;
    };

    switch (row) {
    case 0: { // Binary (8-bit)
        QString s = text;
        s.remove(' ');
        if (s.startsWith("0b", Qt::CaseInsensitive))
            s = s.mid(2);

        bool ok2 = false;
        int v = s.toInt(&ok2, 2);   // ⭐ base = 2
        if (!ok2 || v < 0 || v > 255) return;

        quint8 b = (quint8)v;
        bytes.append((char)b);
        oldLen = 1;
        break;
    }
    case 1: { // Int8
        qint64 v; if (!parseInt64(v)) return;
        qint8 x = (qint8)v;
        bytes.append((char)x);
        oldLen = 1;
        break;
    }
    case 2: { // UInt8
        quint64 v; if (!parseUInt64(v)) return;
        quint8 x = (quint8)v;
        bytes.append((char)x);
        oldLen = 1;
        break;
    }
    case 3: { // Int16
        qint64 v; if (!parseInt64(v)) return;
        qint16 x = (qint16)v;
        quint16 u; memcpy(&u, &x, 2);
        if (BE) u = bswap16(u);
        bytes.append((const char*)&u, 2);
        oldLen = 2;
        break;
    }
    case 4: { // UInt16
        quint64 v; if (!parseUInt64(v)) return;
        quint16 u = (quint16)v;
        if (BE) u = bswap16(u);
        bytes.append((const char*)&u, 2);
        oldLen = 2;
        break;
    }
    case 5: { // Int24
        qint64 v; if (!parseI64(v)) return;
        qint32 x = (qint32)v;
        quint32 u = (quint32)x & 0x00FFFFFFu;
        if (!BE) {
            bytes.append(char(u & 0xFF));
            bytes.append(char((u >> 8) & 0xFF));
            bytes.append(char((u >> 16) & 0xFF));
        } else {
            bytes.append(char((u >> 16) & 0xFF));
            bytes.append(char((u >> 8) & 0xFF));
            bytes.append(char(u & 0xFF));
        }
        oldLen = 3;
        break;
    }
    case 6: { // UInt24
        quint64 v; if (!parseU64(v)) return;
        quint32 u = (quint32)v & 0x00FFFFFFu;
        if (!BE) {
            bytes.append(char(u & 0xFF));
            bytes.append(char((u >> 8) & 0xFF));
            bytes.append(char((u >> 16) & 0xFF));
        } else {
            bytes.append(char((u >> 16) & 0xFF));
            bytes.append(char((u >> 8) & 0xFF));
            bytes.append(char(u & 0xFF));
        }
        oldLen = 3;
        break;
    }
    case 7: { // Int32
        qint64 v; if (!parseInt64(v)) return;
        qint32 x = (qint32)v;
        quint32 u; memcpy(&u, &x, 4);
        if (BE) u = bswap32(u);
        bytes.append((const char*)&u, 4);
        oldLen = 4;
        break;
    }
    case 8: { // UInt32
        quint64 v; if (!parseUInt64(v)) return;
        quint32 u = (quint32)v;
        if (BE) u = bswap32(u);
        bytes.append((const char*)&u, 4);
        oldLen = 4;
        break;
    }
    case 9: { // Int64
        qint64 v; if (!parseInt64(v)) return;
        qint64 x = v;
        quint64 u; memcpy(&u, &x, 8);
        if (BE) u = bswap64(u);
        bytes.append((const char*)&u, 8);
        oldLen = 8;
        break;
    }
    case 10: { // UInt64
        quint64 u; if (!parseUInt64(u)) return;
        if (BE) u = bswap64(u);
        bytes.append((const char*)&u, 8);
        oldLen = 8;
        break;
    }
    case 11: { // SLEB128（可變長）
        qint64 v; if (!parseI64(v)) return;
        bytes = encodeSLEB128(v); // 你已有 decodeSLEB128，這裡需要補 encode（下面我給）
        if (oldLen <= 0)
            oldLen = bytes.size();
        break;
    }
    case 12: { // ULEB128（可變長）
        quint64 v; if (!parseU64(v)) return;
        bytes = encodeULEB128(v); // 同上，需要補 encode（下面我給）
        if (oldLen <= 0)
            oldLen = bytes.size();
        break;
    }
    case 13: { // ASCII：取第一個字元
        if (text.startsWith("0x", Qt::CaseInsensitive)) {
            bool ok2=false;
            int x = text.mid(2).toInt(&ok2,16);
            if (!ok2) return;
            bytes.append(char(x & 0xFF));
        } else {
            bytes.append(text.at(0).toLatin1());
        }
        oldLen = 1;
        break;
    }
    case 14: { // WideChar / char16_t：支援 'A' 或 0x0041 或 U+0041
        quint16 u = 0;
        QString t = text;
        if (t.startsWith("U+", Qt::CaseInsensitive)) t = t.mid(2);
        if (t.startsWith("0x", Qt::CaseInsensitive)) {
            u = (quint16)t.mid(2).toUInt(&ok, 16);
            if (!ok) return;
        } else {
            if (text.isEmpty()) return;

            QChar c = text.at(0);
            u = (quint16)c.unicode();
            // if (!ok) return;
        }
        if (BE) u = bswap16(u);
        bytes.append((const char*)&u, 2);
        oldLen = 2;
        break;
    }
    case 15: { // UTF-8 code point：輸入 U+XXXX 或 0xXXXX 或十進位
        QString t = text.trimmed();
        if (t.isEmpty()) return;

        ok = false;
        quint32 cp = 0;

        auto isAllDigits = [](const QString& s)->bool{
            if (s.isEmpty()) return false;
            for (QChar ch : s) if (!ch.isDigit()) return false;
            return true;
        };

        // 1) code point 模式：U+ / 0x / 純數字
        QString u = t;
        if (u.startsWith("U+", Qt::CaseInsensitive)) {
            u = u.mid(2).trimmed();
            cp = u.toUInt(&ok, 16);
        } else if (u.startsWith("0x", Qt::CaseInsensitive)) {
            u = u.mid(2).trimmed();
            cp = u.toUInt(&ok, 16);
        } else if (isAllDigits(u)) {
            cp = u.toUInt(&ok, 10);
        }

        if (ok) {
            // code point -> UTF-8
            if (cp > 0x10FFFFu) return;                 // 不合法 Unicode
            if (cp >= 0xD800u && cp <= 0xDFFFu) return; // 不允許 surrogate code point
            bytes = QString::fromUcs4(&cp, 1).toUtf8();
        } else {
            // 2) 字元模式：只取第一個 Unicode 字（含 surrogate pair）
            QString first;
            if (t.size() >= 2 && t.at(0).isHighSurrogate() && t.at(1).isLowSurrogate())
                first = t.left(2);
            else
                first = t.left(1);

            bytes = first.toUtf8();
        }

        if (oldLen <= 0)
            oldLen = bytes.size(); // 你的可變長策略：用目前顯示的 bytes 或新 bytes 長度
        break;
    }
    case 16: { // Half Float16：輸入 float，轉 half（你已有 halfToFloat，這裡要補 floatToHalf）
        float f = text.toFloat(&ok); if(!ok) return;
        quint16 h = floatToHalf(f); // 下面我給
        if (BE) h = bswap16(h);
        bytes.append((const char*)&h,2);
        oldLen = 2;
        break;
    }
    case 17: { // Float32：允許 1.23
        float f = text.toFloat(&ok);
        if (!ok) return;
        quint32 u; memcpy(&u, &f, 4);
        if (BE) u = bswap32(u);
        bytes.append((const char*)&u, 4);
        oldLen = 4;
        break;
    }
    case 18: { // Float64
        double d = text.toDouble(&ok);
        if (!ok) return;
        quint64 u; memcpy(&u, &d, 8);
        if (BE) u = bswap64(u);
        bytes.append((const char*)&u, 8);
        oldLen = 8;
        break;
    }
    case 19: { // OLETIME：允許輸入 ISODate 或數字天數
        double days=0;
        QDateTime base(QDate(1899,12,30), QTime(0,0,0), Qt::UTC);
        QDateTime dt = QDateTime::fromString(text, Qt::ISODate);
        if (dt.isValid()) {
            qint64 secs = base.secsTo(dt);
            days = (double)secs / 86400.0;
        } else {
            days = text.toDouble(&ok);
            if(!ok) return;
        }
        quint64 u; memcpy(&u,&days,8);
        if (BE) u = bswap64(u);
        bytes.append((const char*)&u,8);
        oldLen = 8;
        break;
    }
    case 20: { // FILETIME：允許 ISODate 或 64-bit 整數（100ns）
        quint64 ft=0;
        QDateTime base(QDate(1601,1,1), QTime(0,0,0), Qt::UTC);
        QDateTime dt = QDateTime::fromString(text, Qt::ISODate);
        if (dt.isValid()) {
            qint64 secs = base.secsTo(dt);
            ft = (quint64)secs * 10000000ULL;
        } else {
            if (!parseU64(ft)) return;
        }
        quint64 u = ft;
        if (BE) u = bswap64(u);
        bytes.append((const char*)&u,8);
        oldLen = 8;
        break;
    }
    case 21: // DOS Date（ISO yyyy-MM-dd）
    case 22: // DOS Time（HH:mm:ss）
    case 23: { // DOS DateTime（ISO）
        if (row == 21) {
            QDate d = QDate::fromString(text, Qt::ISODate);
            if(!d.isValid()) return;
            quint16 v = (quint16)(((d.year()-1980) & 0x7F) << 9)
                        | (quint16)((d.month() & 0x0F) << 5)
                        | (quint16)(d.day() & 0x1F);
            if (BE) v = bswap16(v);
            bytes.append((const char*)&v,2);
            oldLen = 2;
        } else if (row == 22) {
            QTime t = QTime::fromString(text, "HH:mm:ss");
            if(!t.isValid()) return;
            quint16 v = (quint16)((t.hour() & 0x1F) << 11)
                        | (quint16)((t.minute() & 0x3F) << 5)
                        | (quint16)((t.second()/2) & 0x1F);
            if (BE) v = bswap16(v);
            bytes.append((const char*)&v,2);
            oldLen = 2;
        } else {
            QDateTime dt = QDateTime::fromString(text, Qt::ISODate);
            if(!dt.isValid()) return;
            QDate d = dt.date(); QTime t = dt.time();
            quint16 tv = (quint16)((t.hour() & 0x1F) << 11)
                         | (quint16)((t.minute() & 0x3F) << 5)
                         | (quint16)((t.second()/2) & 0x1F);
            quint16 dv = (quint16)(((d.year()-1980) & 0x7F) << 9)
                         | (quint16)((d.month() & 0x0F) << 5)
                         | (quint16)(d.day() & 0x1F);
            if (BE) { tv = bswap16(tv); dv = bswap16(dv); }
            bytes.append((const char*)&tv,2);
            bytes.append((const char*)&dv,2);
            oldLen = 4;
        }
        break;
    }
    case 24: { // time_t 32
        qint64 v; if (!parseI64(v)) return;
        qint32 x = (qint32)v; quint32 u; memcpy(&u,&x,4);
        if (BE) u = bswap32(u);
        bytes.append((const char*)&u,4); oldLen=4; break;
    }
    case 25: { // time_t 64
        qint64 v; if (!parseI64(v)) return;
        quint64 u; memcpy(&u,&v,8);
        if (BE) u = bswap64(u);
        bytes.append((const char*)&u,8); oldLen=8; break;
    }
    case 26: { // GUID：接受 XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX（按 Windows GUID 規則回寫）
        QString t = text;
        t.remove('{'); t.remove('}'); t.remove('-');
        if (t.size() != 32) return;
        QByteArray hex = QByteArray::fromHex(t.toLatin1());
        if (hex.size() != 16) return;

        // GUID 混合 endian：Data1(4),Data2(2),Data3(2) 走 LE，其餘 8 bytes 原序
        auto sw2 = [](uchar* p){ std::swap(p[0],p[1]); };
        auto sw4 = [](uchar* p){ std::swap(p[0],p[3]); std::swap(p[1],p[2]); };

        uchar tmp[16]; memcpy(tmp, hex.constData(), 16);
        sw4(tmp+0); sw2(tmp+4); sw2(tmp+6);

        bytes = QByteArray((const char*)tmp, 16);
        oldLen=16;
        break;
    }
    default:
        // Disasm 不做 edit，容易出事
        return;
    }

    item->setData(Qt::UserRole + 100, QVariant());

    if (bytes.isEmpty()) return;
    if (oldLen <= 0) oldLen = bytes.size();

    interpretApplyBytes(pos, oldLen, bytes);
}
// =============================================================
