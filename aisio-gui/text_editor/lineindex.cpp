#include "lineindex.h"

#include "../hexadecimal_editor/chunkslite.h"

#include <QtConcurrent>

LineIndex::LineIndex(QObject* parent)
    : QObject(parent)
{
}

void LineIndex::setSource(ChunksLite* chunks)
{
    QWriteLocker lk(&m_lock);
    m_chunks = chunks;
    m_anchors.clear();
    m_anchors.push_back(Anchor{0, 0});
    m_indexedLines = 0;
    m_totalLines = 0;        // unknown until we reach EOF; but keep >=1 by default
}

qint64 LineIndex::totalLines() const
{
    QReadLocker lk(&m_lock);
    return (m_totalLines > 0) ? m_totalLines : 1;
}

qint64 LineIndex::indexedLines() const
{
    QReadLocker lk(&m_lock);
    return m_indexedLines;
}

void LineIndex::ensureIndexedToLine(qint64 line)
{
    if (line < 0) return;
    if (!m_chunks) return;

    // Fast path: already indexed
    {
        QReadLocker lk(&m_lock);
        if (m_totalLines > 0 && line < m_totalLines) return;
        if (line <= m_indexedLines) return;
    }

    if (m_building.testAndSetAcquire(false, true)) {
        // someone else is building
        return;
    }

    // Build in background
    QtConcurrent::run([this, line]() {
        buildUntil(line);
        m_building.storeRelease(false);
        emit indexUpdated();
    });
}

void LineIndex::buildUntil(qint64 targetLine)
{
    ChunksLite* chunks = nullptr;
    qint64 line = 0;
    qint64 offset = 0;
    QVector<Anchor> baseAnchors;

    {
        QReadLocker lk(&m_lock);
        chunks = m_chunks;
        if (!chunks) return;
        if (m_anchors.isEmpty()) {
            baseAnchors.push_back(Anchor{0,0});
        } else {
            baseAnchors = m_anchors;
        }
        const Anchor last = baseAnchors.back();
        line = last.line;
        offset = last.offset;
        // already good
        if (targetLine <= m_indexedLines) return;
    }

    const qint64 size = chunks->size();
    const qint64 CHUNK = 1 * 1024 * 1024;
    const qint64 step = 256;

    QVector<Anchor> newAnchors;

    while (offset < size && line < targetLine) {
        QByteArray buf = chunks->read(offset, CHUNK);
        if (buf.isEmpty())
            break;

        for (int i = 0; i < buf.size(); ++i) {
            if (buf[i] == '\n') {
                ++line;
                if ((line % step) == 0)
                    newAnchors.push_back(Anchor{line, offset + i + 1});
                if (line >= targetLine)
                    break;
            }
        }

        offset += buf.size();
    }

    bool reachedEOF = (offset >= size);

    {
        QWriteLocker lk(&m_lock);

        // append (avoid duplicates if concurrent calls)
        for (const Anchor& a : newAnchors) {
            if (m_anchors.isEmpty() || a.line > m_anchors.back().line)
                m_anchors.push_back(a);
        }

        if (line > m_indexedLines)
            m_indexedLines = line;

        if (reachedEOF) {
            // exact total lines = number of '\n' + 1 (even if file ends with '\n')
            m_totalLines = qMax<qint64>(1, line + 1);
        }
    }
}

qint64 LineIndex::offsetOfLine(qint64 targetLine) const
{
    if (targetLine <= 0) return 0;
    ChunksLite* chunks = nullptr;
    QVector<Anchor> anchors;
    {
        QReadLocker lk(&m_lock);
        chunks = m_chunks;
        anchors = m_anchors;
    }
    if (!chunks) return 0;
    if (anchors.isEmpty()) anchors.push_back(Anchor{0,0});

    const qint64 step = 256;
    const qint64 baseLine = (targetLine / step) * step;

    // find anchor at or before baseLine
    Anchor a{0,0};
    for (int i = anchors.size() - 1; i >= 0; --i) {
        if (anchors[i].line <= baseLine) {
            a = anchors[i];
            break;
        }
    }

    qint64 line = a.line;
    qint64 offset = a.offset;

    const qint64 CHUNK = 64 * 1024;
    const qint64 size = chunks->size();

    while (offset < size && line < targetLine) {
        QByteArray buf = chunks->read(offset, CHUNK);
        if (buf.isEmpty())
            break;
        for (int i = 0; i < buf.size(); ++i) {
            if (buf[i] == '\n') {
                ++line;
                if (line >= targetLine) {
                    return offset + i + 1;
                }
            }
        }
        offset += buf.size();
    }

    return offset;
}

qint64 LineIndex::lineOfOffset(qint64 targetOffset) const
{
    if (targetOffset <= 0) return 0;
    ChunksLite* chunks = nullptr;
    QVector<Anchor> anchors;
    {
        QReadLocker lk(&m_lock);
        chunks = m_chunks;
        anchors = m_anchors;
    }
    if (!chunks) return 0;
    if (anchors.isEmpty()) anchors.push_back(Anchor{0,0});

    // find last anchor with offset <= targetOffset
    Anchor a{0,0};
    for (int i = anchors.size() - 1; i >= 0; --i) {
        if (anchors[i].offset <= targetOffset) {
            a = anchors[i];
            break;
        }
    }

    qint64 line = a.line;
    qint64 offset = a.offset;

    const qint64 CHUNK = 64 * 1024;
    while (offset < targetOffset) {
        qint64 len = qMin<qint64>(CHUNK, targetOffset - offset);
        QByteArray buf = chunks->read(offset, len);
        if (buf.isEmpty())
            break;
        for (char c : buf)
            if (c == '\n') ++line;
        offset += buf.size();
        if (buf.size() < len) break;
    }

    return line;
}
