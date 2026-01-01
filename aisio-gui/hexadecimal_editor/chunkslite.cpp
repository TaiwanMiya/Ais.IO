#include "chunkslite.h"

ChunksLite::ChunksLite(QIODevice *dev)
{
    setDevice(dev);
}

void ChunksLite::setDevice(QIODevice *dev)
{
    m_dev = dev;
    m_chunks.clear();

    if (!m_dev)
        return;

    bool wasOpen = m_dev->isOpen();
    if (!wasOpen)
        m_dev->open(QIODevice::ReadOnly);

    m_size = m_dev->size();

    if (!wasOpen)
        m_dev->close();
}

qint64 ChunksLite::size() const
{
    return m_size;
}

void ChunksLite::clearCache()
{
    m_chunks.clear();
}

QByteArray ChunksLite::read(qint64 offset, qint64 length) const
{
    QByteArray out;
    if (!m_dev || offset < 0 || offset >= m_size || length <= 0)
        return out;

    if (offset + length > m_size)
        length = m_size - offset;

    qint64 chunkBase = offset & ~(CHUNK_SIZE - 1);

    // 1️⃣ 先找 cache
    for (int i = 0; i < m_chunks.size(); ++i) {
        if (m_chunks[i].base == chunkBase) {
            Chunk c = m_chunks.takeAt(i);
            m_chunks.prepend(c); // LRU 提升

            qint64 off = offset - c.base;
            return c.data.mid(off, length);
        }
    }

    // 2️⃣ 沒有 → 從 device 讀
    bool wasOpen = m_dev->isOpen();
    if (!wasOpen)
        m_dev->open(QIODevice::ReadOnly);

    m_dev->seek(chunkBase);
    QByteArray data = m_dev->read(CHUNK_SIZE);

    if (!wasOpen)
        m_dev->close();

    // 3️⃣ 放入 cache
    Chunk c;
    c.base = chunkBase;
    c.data = data;
    m_chunks.prepend(c);

    if (m_chunks.size() > MAX_CHUNKS)
        m_chunks.removeLast();

    qint64 off = offset - chunkBase;
    return data.mid(off, length);
}
