#include "lineindex.h"
#include "../hexadecimal_editor/chunkslite.h"

#include <QtConcurrent>

LineIndex::LineIndex(QObject* parent)
    : QObject(parent)
{
}

void LineIndex::setSource(ChunksLite* chunks)
{
    m_chunks = chunks;
    m_anchors.clear();
    m_indexedLines = 0;
    m_totalLines   = -1;

    if (!m_chunks)
        return;

    // 行 0 → offset 0 一定存在
    m_anchors.push_back({0, 0});
}

qint64 LineIndex::totalLines() const
{
    return (m_totalLines >= 0) ? m_totalLines : m_indexedLines;
}

void LineIndex::ensureIndexedToLine(qint64 line)
{
    if (!m_chunks || line <= m_indexedLines)
        return;

    if (m_building.testAndSetAcquire(false, true)) {
        // already building
        return;
    }

    QtConcurrent::run([this, line]() {
        buildUntil(line);
        m_building.storeRelease(false);
        emit indexUpdated();
    });
}

qint64 LineIndex::offsetOfLine(qint64 line) const
{
    if (!m_chunks)
        return 0;

    // 找最近的小於等於的 anchor
    qint64 idx = 0;
    for (int i = m_anchors.size() - 1; i >= 0; --i) {
        if (m_anchors[i].line <= line) {
            idx = i;
            break;
        }
    }

    qint64 curLine   = m_anchors[idx].line;
    qint64 curOffset = m_anchors[idx].offset;

    if (curLine == line)
        return curOffset;

    // fallback：從 anchor 線性掃（同步，小範圍）
    const qint64 size = m_chunks->size();
    while (curOffset < size && curLine < line) {
        QByteArray buf = m_chunks->read(curOffset, READ_CHUNK);
        if (buf.isEmpty())
            break;

        for (int i = 0; i < buf.size(); ++i) {
            if (buf[i] == '\n') {
                ++curLine;
                if (curLine == line)
                    return curOffset + i + 1;
            }
        }
        curOffset += buf.size();
    }

    return curOffset;
}

void LineIndex::buildUntil(qint64 targetLine)
{
    if (!m_chunks)
        return;

    const qint64 size = m_chunks->size();
    qint64 offset = m_anchors.last().offset;
    qint64 line   = m_anchors.last().line;

    while (offset < size && line < targetLine) {
        QByteArray buf = m_chunks->read(offset, READ_CHUNK);
        if (buf.isEmpty())
            break;

        for (int i = 0; i < buf.size(); ++i) {
            if (buf[i] == '\n') {
                ++line;

                if (line % ANCHOR_STEP == 0) {
                    m_anchors.push_back({ line, offset + i + 1 });
                }
            }
        }

        offset += buf.size();
    }

    m_indexedLines = line;

    // 若掃到 EOF，補 totalLines
    if (offset >= size && m_totalLines < 0) {
        // 若檔案最後是 '\n'，代表還有一個空行
        if (size > 0) {
            QByteArray last = m_chunks->read(size - 1, 1);
            if (!last.isEmpty() && last[0] == '\n')
                ++line;
        }
        m_totalLines = line;
    }
}
