#include "textviewport.h"
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QPainter>
#include <QScrollBar>
#include <QtConcurrent>
#include <QTimer>
#include <QStyle>
#include <QKeyEvent>

static inline qint64 countNewlines(const QByteArray& b, int upto)
{
    qint64 n = 0;
    upto = qBound(0, upto, b.size());
    for (int i = 0; i < upto; ++i)
        if (b[i] == '\n') ++n;
    return n;
}

TextViewport::TextViewport(QWidget* parent)
    : QAbstractScrollArea(parent),
    m_font(QFontDatabase::systemFont(QFontDatabase::FixedFont)),
    m_fm(m_font)
{
    // 字體與大小
    QFont f("Consolas");
    f.setPointSize(12);
    setFont(f);

    // 深色
    setAutoFillBackground(true);
    QPalette pal = palette();
    pal.setColor(QPalette::Base, QColor(30, 30, 30));
    pal.setColor(QPalette::Text, Qt::white);
    setPalette(pal);
    viewport()->setPalette(pal);

    m_lineHeight = m_fm.height();
    verticalScrollBar()->setSingleStep(1);
}

void TextViewport::setFont(const QFont& f)
{
    m_font = f;
    m_fm = QFontMetrics(m_font);
    m_lineHeight = m_fm.height();
    viewport()->update();
}

void TextViewport::createSearchPanel()
{
    if (m_searchPanel) return;

    m_searchPanel = new QWidget(this);
    m_searchPanel->setAutoFillBackground(true);

    QPalette pal = m_searchPanel->palette();
    pal.setColor(QPalette::Window, QColor(40, 40, 40, 230));
    m_searchPanel->setPalette(pal);
    m_searchPanel->setAttribute(Qt::WA_StyledBackground, true);
    m_searchPanel->setStyleSheet(
        "QWidget { border: 1px solid #666666; border-radius: 4px; }"
        "QLineEdit[flashError=\"true\"] { background:#330000; color:#ff8080; }"
        "QToolButton { background-color: #333333; color: #ffffff; border: 1px solid #555555; padding: 0 6px; }"
        "QToolButton:hover { background-color: #444444; }"
        );
    m_searchPanel->installEventFilter(this);

    auto layout = new QHBoxLayout(m_searchPanel);
    layout->setContentsMargins(6, 4, 6, 4);
    layout->setSpacing(4);

    m_findEdit = new QLineEdit(m_searchPanel);
    m_findEdit->setPlaceholderText(tr("Find..."));

    m_btnFindPrev = new QToolButton(m_searchPanel);
    m_btnFindPrev->setText("◀");

    m_btnFindNext = new QToolButton(m_searchPanel);
    m_btnFindNext->setText("▶");

    m_gotoEdit = new QLineEdit(m_searchPanel);
    m_gotoEdit->setPlaceholderText(tr("Goto line...")); // 1-based
    m_btnGoto = new QToolButton(m_searchPanel);
    m_btnGoto->setText(tr("Go"));

    layout->addWidget(m_findEdit, 1);
    layout->addWidget(m_btnFindPrev);
    layout->addWidget(m_btnFindNext);
    layout->addSpacing(8);
    layout->addWidget(m_gotoEdit);
    layout->addWidget(m_btnGoto);

    m_searchPanel->hide();

    connect(m_findEdit, &QLineEdit::textEdited, this, [this](const QString&) {
        resetFindState();
    });

    connect(m_btnFindNext, &QToolButton::clicked, this, [this]() {
        if (!m_findEdit) return;
        startFindAsync(m_findEdit->text().toUtf8(), false);
    });
    connect(m_btnFindPrev, &QToolButton::clicked, this, [this]() {
        if (!m_findEdit) return;
        startFindAsync(m_findEdit->text().toUtf8(), true);
    });
    connect(m_findEdit, &QLineEdit::returnPressed, this, [this]() {
        if (!m_findEdit) return;
        startFindAsync(m_findEdit->text().toUtf8(), false);
    });

    auto doGoto = [this]() {
        if (!m_gotoEdit) return;
        bool ok=false;
        qint64 line1 = m_gotoEdit->text().trimmed().toLongLong(&ok);
        if (!ok || line1 <= 0) {
            m_gotoEdit->setProperty("flashError", true);
            m_gotoEdit->style()->unpolish(m_gotoEdit);
            m_gotoEdit->style()->polish(m_gotoEdit);
            return;
        }
        // 1-based -> 0-based
        verticalScrollBar()->setValue(int(line1 - 1));
        viewport()->update();
    };
    connect(m_btnGoto, &QToolButton::clicked, this, doGoto);
    connect(m_gotoEdit, &QLineEdit::returnPressed, this, doGoto);

    // caret blink
    if (!m_caretTimer) {
        m_caretTimer = new QTimer(this);
        m_caretTimer->setInterval(500);
        connect(m_caretTimer, &QTimer::timeout, this, [this]() {
            m_caretOn = !m_caretOn;
            viewport()->update();
        });
    }
}

void TextViewport::resetFindState()
{
    m_lastFindOffset = -1;
    m_matchOffset = -1;
    m_matchLen = 0;
    viewport()->update();
}

void TextViewport::openSearchPanel()
{
    createSearchPanel();
    if (!m_searchPanel) return;

    // 放右下角，像 HexView 的浮動條
    const int w = width();
    const int h = height();
    const int ph = 34;
    m_searchPanel->setGeometry(10, h - ph - 10, w - 20, ph);

    m_searchPanel->show();
    m_searchPanel->raise();
    if (m_findEdit) {
        m_findEdit->setFocus();
        m_findEdit->selectAll();
    }
}

void TextViewport::openGotoPanel()
{
    createSearchPanel();
    if (!m_searchPanel) return;

    const int w = width();
    const int h = height();
    const int ph = 34;
    m_searchPanel->setGeometry(10, h - ph - 10, w - 20, ph);
    m_searchPanel->show();
    m_searchPanel->raise();
    if (m_gotoEdit) {
        m_gotoEdit->setFocus();
        m_gotoEdit->selectAll();
    }
}

void TextViewport::findNext()
{
    if (!m_chunks || !m_overlay) return;

    // // 起點：若之前找過，就從上次命中 +1；否則從目前畫面頂端行開始
    // qint64 startLine  = verticalScrollBar()->value();
    // qint64 startOff   = findLineOffset(startLine);

    // if (m_lastFindOffset >= 0) {
    //     startOff  = m_lastFindOffset + 1;
    //     startLine = m_lastFindLine; // 粗略即可（精確 line 由 job 算）
    // }

    // startFindJob(pattern, startOff, false);

    createSearchPanel();
    if (!m_findEdit) return;
    startFindAsync(m_findEdit->text().toUtf8(), false);
}

void TextViewport::findPrev()
{
    if (!m_chunks || !m_overlay) return;

    // qint64 startLine = verticalScrollBar()->value();
    // qint64 startOff  = findLineOffset(startLine);

    // if (m_lastFindOffset >= 0) {
    //     startOff  = m_lastFindOffset - 1;
    //     startLine = m_lastFindLine;
    // }

    // if (startOff < 0) startOff = 0;

    // startFindJob(pattern, startOff, true);

    createSearchPanel();
    if (!m_findEdit) return;
    startFindAsync(m_findEdit->text().toUtf8(), true);
}

void TextViewport::gotoLine(qint64 line) {
    if (!m_lineIndex) return;
    m_lineIndex->ensureIndexedToLine(line);
    verticalScrollBar()->setValue(line);
    viewport()->update();
}

void TextViewport::setSource(ChunksLite* chunks, OverlayMap* overlay)
{
    m_chunks = chunks;
    m_overlay = overlay;

    if (!m_lineIndex)
        m_lineIndex = new LineIndex(this);

    m_lineIndex->setSource(m_chunks);

    QObject::disconnect(m_lineIndex, nullptr, this, nullptr);
    connect(m_lineIndex, &LineIndex::indexUpdated, this, &TextViewport::updateViewport, Qt::QueuedConnection);

    const qint64 size = overlay->size();

    // 抽樣前 4MB 估換行密度，避免 size/80 低估
    const qint64 sampleLen = qMin<qint64>(size, 4LL * 1024 * 1024);
    QByteArray sample = m_overlay->read(0, sampleLen, m_chunks);

    qint64 nlCount = 0;
    for (char c : sample)
        if (c == '\n') ++nlCount;

    // 平均行長（偏向「不要太大」以免低估行數）
    qint64 avg = (nlCount > 0) ? (sampleLen / nlCount) : 80;
    if (avg < 1) avg = 1;
    if (avg > 256) avg = 256; // ✅ 卡住：避免 m_totalLines 太小

    // 先給一個保守值，避免 scrollbar 空掉
    m_totalLines = qMax<qint64>(m_totalLines, 1);
    updateScrollBar();
    viewport()->update();

    // ✅ 精確行數：背景掃 base，不用 overlay（不會卡 UI）
    if (!m_countingLines && m_chunks) {
        m_countingLines = true;

        QObject::disconnect(&m_lineCountWatcher, nullptr, this, nullptr);
        connect(&m_lineCountWatcher, &QFutureWatcher<qint64>::finished,
                this, [this]() {
                    const qint64 lines = m_lineCountWatcher.result();
                    m_totalLines = qMax<qint64>(lines, 1);
                    m_countingLines = false;
                    updateScrollBar();
                    viewport()->update();
                });

        auto future = QtConcurrent::run([chunks = m_chunks]() -> qint64 {
            const qint64 size = chunks->size();
            const qint64 CHUNK = 1 * 1024 * 1024;

            qint64 offset = 0;
            qint64 lines = 1;

            while (offset < size) {
                QByteArray buf = chunks->read(offset, CHUNK);
                if (buf.isEmpty())
                    break;

                for (char c : buf)
                    if (c == '\n')
                        ++lines;

                offset += buf.size();
            }

            return lines;
        });

        m_lineCountWatcher.setFuture(future);
    }
}

void TextViewport::resizeEvent(QResizeEvent*)
{
    m_visibleLines = viewport()->height() / m_lineHeight;
    updateScrollBar();
}

bool TextViewport::eventFilter(QObject* obj, QEvent* ev)
{
    if (obj == m_searchPanel) {
        if (ev->type() == QEvent::KeyPress) {
            auto* ke = static_cast<QKeyEvent*>(ev);
            if (ke->key() == Qt::Key_Escape) {
                m_searchPanel->hide();
                viewport()->setFocus();
                return true;
            }
        }
    }
    return QAbstractScrollArea::eventFilter(obj, ev);
}

void TextViewport::updateScrollBar()
{
    verticalScrollBar()->setRange(0,
                                  qMax<qint64>(0, m_totalLines - m_visibleLines));
    verticalScrollBar()->setPageStep(m_visibleLines);
}

void TextViewport::updateViewport()
{
    m_totalLines = m_lineIndex->totalLines();
    updateScrollBar();
    viewport()->update();
}

void TextViewport::paintEvent(QPaintEvent*)
{
    if (!m_chunks || !m_overlay)
        return;

    QPainter p(viewport());
    p.setFont(m_font);
    p.setPen(palette().text().color());

    paintLines(p);
}

void TextViewport::paintLines(QPainter& p)
{
    const int firstLine = verticalScrollBar()->value();
    qint64 offset = (m_lineIndex ? m_lineIndex->offsetOfLine(firstLine)
                                : findLineOffset(firstLine));
    const qint64 size = m_overlay->size();

    for (int i = 0; i < m_visibleLines; ++i) {
        // ⭐ EOF 空行（一定要最前面）
        if (offset == size && firstLine + i < m_totalLines) {
            const int y = (i + 1) * m_lineHeight;
            p.setPen(Qt::gray);
            p.drawText(0, y, QString::number(firstLine + i + 1).rightJustified(6));
            continue;
        }

        if (offset >= size)
            break;

        const qint64 lineStartOff = offset;

        QByteArray buf = m_overlay->read(offset, 64 * 1024, m_chunks);
        if (buf.isEmpty())
            break;

        const int nlPos = buf.indexOf('\n');
        QByteArray lineBytes;
        qint64 lineEndOff = lineStartOff;

        if (nlPos >= 0) {
            lineBytes = buf.left(nlPos);
            lineEndOff = lineStartOff + nlPos;  // 不含 '\n'
            offset = lineEndOff + 1;            // skip '\n'
        } else {
            lineBytes = buf;
            lineEndOff = lineStartOff + buf.size();
            offset = lineEndOff;
        }

        const QString line = QString::fromUtf8(lineBytes);
        const int yText = (i + 1) * m_lineHeight;

        p.setPen(Qt::gray);
        p.drawText(0, yText, QString::number(firstLine + i + 1).rightJustified(6));
        p.setPen(palette().text().color());
        p.drawText(60, yText, line);

        // ✅ highlight if match overlaps this line range
        if (m_matchOffset >= 0 && m_matchLen > 0) {
            const qint64 m0 = m_matchOffset;
            const qint64 m1 = m_matchOffset + m_matchLen;

            if (m0 < lineEndOff && m1 > lineStartOff) {
                const qint64 col0 = qMax<qint64>(0, m0 - lineStartOff);
                const qint64 col1 = qMin<qint64>(lineBytes.size(), m1 - lineStartOff);

                const QString left = QString::fromUtf8(lineBytes.left(int(col0)));
                const QString mid  = QString::fromUtf8(lineBytes.mid(int(col0), int(col1 - col0)));

                const int x0 = 60 + m_fm.horizontalAdvance(left);
                const int w  = m_fm.horizontalAdvance(mid);
                const int y0 = i * m_lineHeight;

                p.fillRect(QRect(x0, y0, qMax(2, w), m_lineHeight), QColor(80, 80, 160, 120));
                if (m_caretOn)
                    p.fillRect(QRect(x0, y0, 2, m_lineHeight), QColor(200, 220, 255, 220));
            }
        }
    }
}

qint64 TextViewport::findLineOffset(qint64 targetLine) {
    if (!m_overlay) return 0;

    const qint64 size  = m_overlay->size();
    const qint64 CHUNK = 64 * 1024;

    qint64 offset = 0;
    qint64 line   = 0;

    while (offset < size && line < targetLine) {
        QByteArray buf = m_overlay->read(offset, CHUNK);
        if (buf.isEmpty())
            break;

        int idx = 0;
        bool advanced = false;

        while (idx < buf.size() && line < targetLine) {
            int nl = buf.indexOf('\n', idx);
            if (nl < 0)
                break;

            idx = nl + 1;
            ++line;
            advanced = true;
        }

        if (advanced) {
            offset += idx;            // 找到至少一個 '\n'，走到最後一個 '\n' 後
        } else {
            offset += buf.size();     // ✅ 這塊完全沒有 '\n'：整塊跳過，避免 offset 不動卡死
        }
    }

    return offset;
}

// void TextViewport::startFindJob(const QByteArray& pat, qint64 startOffset, bool backwards)
// {
//     if (m_findRunning) return;
//     if (!m_chunks || !m_overlay) return;
//     if (pat.isEmpty()) return;

//     const qint64 size = m_overlay->size();
//     if (size <= 0) return;

//     if (startOffset < 0) startOffset = 0;
//     if (startOffset > size) startOffset = size;

//     m_findRunning = true;
//     emit progressStarted();

//     QObject::disconnect(&m_findWatcher, nullptr, this, nullptr);
//     connect(&m_findWatcher, &QFutureWatcher<QPair<qint64,qint64>>::finished,
//             this, [this]() {
//                 const auto r = m_findWatcher.result();
//                 const qint64 off  = r.first;
//                 const qint64 line = r.second;

//                 m_findRunning = false;
//                 emit progressFinished();

//                 if (off >= 0) {
//                     m_lastFindOffset = off;
//                     m_lastFindLine   = line;

//                     // 像 HexView：跳到結果位置（這裡是 line-based）
//                     verticalScrollBar()->setValue((int)line);
//                     viewport()->update();

//                     emit findFinished(true, line, off);
//                 } else {
//                     emit findFinished(false, -1, -1);
//                 }
//             });

//     // 捕捉目前畫面行，用於 forward job 起算 line（避免從 0 算到尾端）
//     const qint64 startLine = verticalScrollBar()->value();

//     auto future = QtConcurrent::run([=]() -> QPair<qint64,qint64> {
//         const qint64 CHUNK = 1 * 1024 * 1024;
//         const int patLen = pat.size();
//         if (patLen <= 0) return {-1, -1};

//         if (!backwards) {
//             qint64 curOff  = startOffset;
//             qint64 curLine = startLine;

//             while (curOff < size) {
//                 const qint64 winLen = qMin<qint64>(CHUNK + patLen - 1, size - curOff);
//                 QByteArray win = m_overlay->read(curOff, winLen, m_chunks);
//                 if (win.isEmpty()) break;

//                 int idx = win.indexOf(pat);
//                 // 只接受 idx < CHUNK，避免命中落在 overlap 區造成重複/錯位
//                 while (idx >= 0 && idx >= CHUNK)
//                     idx = win.indexOf(pat, idx + 1);

//                 if (idx >= 0) {
//                     const qint64 foundOff  = curOff + idx;
//                     const qint64 addLines  = countNewlines(win, idx);
//                     const qint64 foundLine = curLine + addLines;
//                     return {foundOff, foundLine};
//                 }

//                 // advance：只吃前 CHUNK（不包含 overlap，避免重複計 newline）
//                 const int adv = qMin<int>((int)CHUNK, win.size());
//                 curLine += countNewlines(win, adv);
//                 curOff  += adv;
//             }

//             return {-1, -1};
//         } else {
//             // backward：用 block 往回找 offset，找到後再算 line
//             qint64 pos = startOffset;
//             if (pos >= size) pos = size - 1;

//             while (pos >= 0) {
//                 const qint64 blockStart = qMax<qint64>(0, pos - CHUNK + 1);
//                 const qint64 len = pos - blockStart + 1;

//                 QByteArray buf = m_overlay->read(blockStart, len, m_chunks);
//                 if (buf.isEmpty()) break;

//                 int idx = buf.lastIndexOf(pat);
//                 if (idx >= 0) {
//                     const qint64 foundOff = blockStart + idx;

//                     // 算 line：從最近 anchor offset 向前掃到 foundOff（只做一次，不會卡 UI）
//                     qint64 lineBase = 0;
//                     qint64 offBase  = 0;

//                     // 用 lineIndex 找「離 foundOff 最近的行錨點」：用 offsetOfLine 反推不方便
//                     // v1 先退一步：用目前可用的 offsetOfLine(0)=0 當 base（之後我們再做 lineOfOffset 加速）
//                     lineBase = 0;
//                     offBase  = 0;

//                     qint64 line = lineBase;
//                     qint64 off  = offBase;

//                     const qint64 STEP = 1 * 1024 * 1024;
//                     while (off < foundOff) {
//                         const qint64 n = qMin<qint64>(STEP, foundOff - off);
//                         QByteArray t = m_overlay->read(off, n, m_chunks);
//                         if (t.isEmpty()) break;
//                         for (char c : t) if (c == '\n') ++line;
//                         off += t.size();
//                     }

//                     return {foundOff, line};
//                 }

//                 pos = blockStart - 1;
//             }

//             return {-1, -1};
//         }
//     });

//     m_findWatcher.setFuture(future);
// }

void TextViewport::startFindAsync(const QByteArray& pat, bool backwards)
{
    if (!m_chunks || !m_overlay) return;
    if (pat.isEmpty()) return;
    if (m_findRunning) return;

    const qint64 size = m_overlay->size();
    if (size <= 0) return;

    // Start position (respect direction)
    qint64 startOff = 0;
    if (m_lastFindOffset >= 0) {
        startOff = backwards ? (m_lastFindOffset - 1) : (m_lastFindOffset + 1);
    } else {
        const int curLine = verticalScrollBar()->value();
        startOff = m_lineIndex ? m_lineIndex->offsetOfLine(curLine) : findLineOffset(curLine);
    }

    if (startOff < 0) startOff = 0;
    if (startOff >= size) startOff = size - 1;

    m_findRunning = true;
    emit progressStarted();

    QObject::disconnect(&m_findWatcher, nullptr, this, nullptr);
    connect(&m_findWatcher, &QFutureWatcher<qint64>::finished,
            this, [this, pat, backwards]() {
                const qint64 off = m_findWatcher.result();
                m_findRunning = false;
                emit progressFinished();

                if (off < 0) {
                    // 找不到 → flash error
                    if (m_findEdit) {
                        m_findEdit->setProperty("flashError", true);
                        m_findEdit->style()->unpolish(m_findEdit);
                        m_findEdit->style()->polish(m_findEdit);
                    }
                    emit findFinished(false, -1, -1);
                    return;
                }

                // 命中：更新狀態 + 視覺高亮
                m_lastFindOffset = off;
                m_matchOffset = off;
                m_matchLen = pat.size();

                qint64 line = -1;
                if (m_lineIndex) {
                    // ensure index reaches the area; lineOfOffset will scan from closest anchor
                    line = m_lineIndex->lineOfOffset(off);
                }
                if (line >= 0) {
                    m_lastFindLine = line;
                    verticalScrollBar()->setValue(int(line));
                }

                if (m_caretTimer) m_caretTimer->start();
                viewport()->update();
                emit findFinished(true, line, off);
            });

    auto future = QtConcurrent::run([overlay = m_overlay, chunks = m_chunks,
                                    pat, backwards, size, startOff]() -> qint64 {
        const qint64 BLOCK = 1 * 1024 * 1024;
        const qint64 overlap = qMax(0, pat.size() - 1);

        if (!backwards) {
            qint64 pos = startOff;
            while (pos < size) {
                const qint64 chunkStart = (pos / BLOCK) * BLOCK;
                const qint64 chunkEnd = qMin<qint64>(size, chunkStart + BLOCK + overlap);
                const qint64 len = chunkEnd - chunkStart;
                QByteArray buf = overlay->read(chunkStart, len, chunks);
                if (buf.size() != len) break;

                const int from = int(qMax<qint64>(0, pos - chunkStart));
                const int idx = buf.indexOf(pat, from);
                if (idx >= 0) return chunkStart + idx;

                // next block
                pos = chunkStart + BLOCK;
            }
            return -1;
        } else {
            qint64 pos = startOff;
            while (pos >= 0) {
                const qint64 baseStart = (pos / BLOCK) * BLOCK;
                const qint64 chunkStart = qMax<qint64>(0, baseStart - overlap);
                const qint64 chunkEnd = qMin<qint64>(size, baseStart + BLOCK + overlap);
                const qint64 len = chunkEnd - chunkStart;
                QByteArray buf = overlay->read(chunkStart, len, chunks);
                if (buf.size() != len) break;

                qint64 maxFrom = qMin<qint64>(pos - chunkStart, len - pat.size());
                if (maxFrom < 0) maxFrom = len - pat.size();
                const int idx = buf.lastIndexOf(pat, int(maxFrom));
                if (idx >= 0) return chunkStart + idx;

                if (chunkStart == 0) break;
                pos = chunkStart - 1;
            }
            return -1;
        }
    });

    m_findWatcher.setFuture(future);
}
