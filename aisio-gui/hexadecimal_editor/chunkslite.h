#ifndef CHUNKS_LITE_H
#define CHUNKS_LITE_H

#include <QIODevice>
#include <QByteArray>
#include <QHash>
#include <QList>
#include <QMutex>

// 原始檔案 (只讀、不修改)
class ChunksLite
{
public:
    explicit ChunksLite(QIODevice *dev = nullptr);

    void setDevice(QIODevice *dev);
    qint64 size() const;

    QByteArray read(qint64 offset, qint64 length) const;
    QIODevice* getDevice() { return m_dev; }

    void clearCache();

private:
    struct Chunk {
        qint64 base;        // chunk 起始 offset
        QByteArray data;    // chunk 內容
    };

    QIODevice *m_dev = nullptr;
    qint64     m_size = 0;

    static constexpr qint64 CHUNK_SIZE = 0x10000; // 64 KB
    static constexpr int   MAX_CHUNKS  = 64;      // LRU 上限

    mutable QList<Chunk> m_chunks; // 簡單 LRU（足夠用）
    mutable QMutex m_mutex;
};

#endif // CHUNKS_LITE_H
