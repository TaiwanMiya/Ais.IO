#pragma once

#include <QObject>
#include <QVector>
#include <QAtomicInteger>

class ChunksLite;

class LineIndex : public QObject
{
    Q_OBJECT
public:
    explicit LineIndex(QObject* parent = nullptr);

    void setSource(ChunksLite* chunks);

    // 確保 index 至少建到指定行（背景）
    void ensureIndexedToLine(qint64 line);

    // 同步查詢（若尚未建到，會退化為線性掃描）
    qint64 offsetOfLine(qint64 line) const;

    qint64 totalLines() const;

signals:
    void indexUpdated();

private:
    void buildUntil(qint64 targetLine);

private:
    struct Anchor {
        qint64 line;
        qint64 offset;
    };

    ChunksLite* m_chunks = nullptr;

    QVector<Anchor> m_anchors;
    qint64 m_indexedLines = 0;
    qint64 m_totalLines   = -1; // unknown

    QAtomicInteger<bool> m_building { false };

    static constexpr qint64 ANCHOR_STEP = 1024;     // 每 1024 行一個錨點
    static constexpr qint64 READ_CHUNK  = 1 << 20;  // 1MB
};
