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
#include <QRegularExpression>
#include <QInputDialog>

#include <QLineEdit>
#include <QComboBox>
#include <QToolButton>
#include <QHBoxLayout>
#include <QLabel>

HexView::HexView(QWidget *parent)
    : QAbstractScrollArea(parent)
{
    // 用系統等寬字型
    // QFont f = QFontDatabase::systemFont(QFontDatabase::FixedFont);
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

    new QShortcut(QKeySequence("Ctrl+Z"), this, [this](){ this->undo(); });
    new QShortcut(QKeySequence("Ctrl+Y"), this, [this](){ this->redo(); });
    new QShortcut(QKeySequence("Ctrl+C"), this, [this](){ this->copySelectionToClipboard(); });
    new QShortcut(QKeySequence("Ctrl+V"), this, [this](){ this->pasteFromClipboard(); });

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

        if (m_lineEditFlashCount <= 0) {
            m_lineEditFlashing->setStyleSheet(m_lineEditOriginalStyle);
            m_lineEditFlashing = nullptr;
            m_lineEditFlashTimer->stop();
            return;
        }

        if (m_lineEditFlashCount % 2 == 0) {
            m_lineEditFlashing->setStyleSheet("QLineEdit { background:#330000; color:#ff8080; }");
        } else {
            m_lineEditFlashing->setStyleSheet((m_lineEditOriginalStyle));
        }

        m_lineEditFlashCount--;
    });

    updateMetrics();
    createSearchPanel();
    setupSearchShortcuts();
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

    QFontMetrics fm(font());
    int headerHeight = fm.height();

    int vpos = verticalScrollBar()->value();

    // Y → 行號
    int y = p.y() - headerHeight - m_topMargin;
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
    if (text.isEmpty() || m_data.isEmpty())
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
    if (!newPattern && m_lastPos >= 0) {
        // 延續同一個 pattern 的搜尋
        start = backwards ? (m_lastPos - 1) : m_lastPos;
        if (start < 0) start = 0;
    } else {
        // 新 pattern：以目前游標 / 選取為基準
        if (hasSelection())
            start = backwards ? m_selStart : m_selEnd;
        else
            start = m_cursorOffset;
    }

    // 3) 真正執行搜尋（這裡呼叫你原本的 findBytes）
    qint64 pos = findBytes(pattern, start, backwards);
    if (pos >= 0) {
        m_lastPattern = pattern;
        m_lastPos     = pos + (backwards ? 0 : pattern.size());
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
        "QLineEdit, QComboBox { background-color: #1e1e1e; color: #ffffff; border: 1px solid #555555; }"
        "QToolButton { background-color: #333333; color: #ffffff; border: 1px solid #555555; padding: 0 6px; }"
        "QToolButton:hover { background-color: #444444; }"
        );

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
    QRect vpRect = viewport()->geometry();
    const int margin = 8;

    QPoint topLeft = QPoint(vpRect.left() + margin,
                            vpRect.top()  + margin);

    m_searchPanel->move(topLeft);
    m_searchPanel->raise();
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
    if (!m_data.isEmpty() && m_bytesPerLine > 0) {
        totalLines = (m_data.size() + m_bytesPerLine - 1) / m_bytesPerLine;
    }

    int linesPerPage = 1;
    if (m_lineHeight > 0) {
        linesPerPage = qMax(1, (viewport()->height() - headerHeight - m_topMargin * 2) / m_lineHeight);
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
        QRect asciiRect(ax, 0, m_charWidth, m_lineHeight);

        bool hasSel = (m_selStart >= 0 && m_selEnd > m_selStart) ||
                      !m_extraSelections.isEmpty();

        bool inSelection = byteInAnySelection(off);

        // 如果有選取 → 不畫游標
        bool isCursor = (!hasSel && m_showCursor && off == m_cursorOffset);


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

    if (m_data.isEmpty() || m_lineHeight <= 0 || m_bytesPerLine <= 0)
        return;

    int vpos = verticalScrollBar()->value();

    int linesPerPage = qMax(1, (viewport()->height() - headerHeight - m_topMargin * 2) / m_lineHeight);
    int byteCount    = m_data.size();
    int totalLines   = (byteCount + m_bytesPerLine - 1) / m_bytesPerLine;
    int lastLine     = qMin(vpos + linesPerPage, totalLines);

    // === 把每一行畫到 header 底下 ===
    int baseY = headerHeight + m_topMargin;

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

    QFontMetrics fm(font());
    int headerHeight = fm.height();
    int linesPerPage = (viewport()->height() - headerHeight - m_topMargin * 2) / m_lineHeight;
    if (linesPerPage <= 0) linesPerPage = 1;

    int firstLine    = v->value();
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

void HexView::flashLineEditError(QLineEdit *edit) {
    if (!edit) return;

    m_lineEditFlashing = edit;
    m_lineEditFlashCount = 5; // 閃 5 次 (紅 -> 白 -> 紅 -> 白)
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
    case Qt::Key_Return:
    case Qt::Key_Enter:
        // Enter / Return 不當成 Hex / ASCII 輸入
        // 若焦點在搜尋欄，Qt 會自己觸發 QLineEdit::returnPressed，
        // 我們這裡直接忽略，不要再往下丟給 handleHexEdit。
        event->ignore();
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
        m_showCursor = true;

        // ⭐ 搜尋成功 → 黃色閃爍整個選取
        m_searchFlashCounter = 3;
        m_errorFlashTimer->start();

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

    m_cursorOffset = offset;

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

    if (m_findEdit)
        m_findEdit->setStyleSheet("");

    return pos;
}

qint64 HexView::findPrev(const QString &input)
{
    qint64 pos = doFindInternal(input, true);

    if (pos < 0) {
        flashLineEditError(m_findEdit);
        return -1;
    }

    if (m_findEdit)
        m_findEdit->setStyleSheet("");

    return pos;
}

qint64 HexView::gotoOffsetFromText(const QString &t)
{
    QString s = t.trimmed();
    if (s.isEmpty() || m_data.isEmpty())
        return -1;

    bool ok = false;
    qint64 value = 0;

    if (s.startsWith("0x", Qt::CaseInsensitive)) {
        value = s.mid(2).toLongLong(&ok, 16);
    } else if (s.contains(QRegularExpression("[A-Fa-f]"))) {
        value = s.toLongLong(&ok, 16);
    } else {
        value = s.toLongLong(&ok, 10);
    }

    if (!ok || value < 0 || value >= m_data.size()){
        flashLineEditError(m_findEdit);
        return -1;
    }

    if (m_gotoEdit)
        m_gotoEdit->setStyleSheet("");

    gotoOffset(value);  // ⭐ 你原本的 API：把 cursor & 視圖移到指定位移
    return value;
}
