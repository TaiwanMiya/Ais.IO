#include "diffnavigator.h"
#include "overlaymap.h"

#include <algorithm>
#include <cstring>

void DiffNavigator::setSources(OverlayMap* left, OverlayMap* right) {
    this->m_left = left;
    this->m_right = right;
}

qint64 DiffNavigator::size() const
{
    if (!m_left || !m_right) return 0;
    return std::max(m_left->size(), m_right->size());
}

bool DiffNavigator::findNext(qint64 fromOffset, qint64& outOffset)
{
    return scanForward(fromOffset, outOffset);
}

bool DiffNavigator::findPrev(qint64 fromOffset, qint64& outOffset)
{
    return scanBackward(fromOffset, outOffset);
}

bool DiffNavigator::scanForward(qint64 start, qint64& out)
{
    if (!m_left || !m_right) return false;

    const qint64 ls = m_left->size();
    const qint64 rs = m_right->size();
    const qint64 maxSize = std::max(ls, rs);
    if (maxSize <= 0) return false;

    if (start < 0) start = 0;
    if (start >= maxSize) return false;

    qint64 pos = start;

    while (pos < maxSize) {
        const qint64 blockStart = (pos / CHUNK) * CHUNK;
        const qint64 blockEnd   = std::min(blockStart + CHUNK, maxSize);
        const qint64 len        = blockEnd - blockStart;

        const qint64 lLen = (blockStart < ls) ? std::min(len, ls - blockStart) : 0;
        const qint64 rLen = (blockStart < rs) ? std::min(len, rs - blockStart) : 0;

        const QByteArray a = (lLen > 0) ? m_left->read(blockStart, lLen) : QByteArray();
        const QByteArray b = (rLen > 0) ? m_right->read(blockStart, rLen) : QByteArray();

        // 只有兩邊都完整讀到且 memcmp=0 才能整塊跳過
        if (a.size() == len && b.size() == len &&
            std::memcmp(a.constData(), b.constData(), size_t(len)) == 0) {
            pos = blockEnd;
            continue;
        }

        // 從 pos 在此 block 的位置開始往後逐 byte（保證不漏）
        qint64 i0 = pos - blockStart;
        for (qint64 i = i0; i < len; ++i) {
            const qint64 cur = blockStart + i;

            const bool inL = (cur < ls);
            const bool inR = (cur < rs);
            if (inL != inR) { out = cur; return true; }

            // 都存在才比較 byte
            const char av = (i < a.size()) ? a[int(i)] : 0;
            const char bv = (i < b.size()) ? b[int(i)] : 0;
            if (av != bv) { out = cur; return true; }
        }

        pos = blockEnd;
    }

    return false;
}

bool DiffNavigator::scanBackward(qint64 start, qint64& out)
{
    if (!m_left || !m_right) return false;

    const qint64 ls = m_left->size();
    const qint64 rs = m_right->size();
    const qint64 maxSize = std::max(ls, rs);
    if (maxSize <= 0) return false;

    if (start >= maxSize) start = maxSize - 1;
    if (start < 0) return false;

    qint64 pos = start;

    while (pos >= 0) {
        const qint64 blockStart = (pos / CHUNK) * CHUNK;
        const qint64 blockEnd   = std::min(blockStart + CHUNK, maxSize);
        const qint64 len        = blockEnd - blockStart;

        const qint64 lLen = (blockStart < ls) ? std::min(len, ls - blockStart) : 0;
        const qint64 rLen = (blockStart < rs) ? std::min(len, rs - blockStart) : 0;

        const QByteArray a = (lLen > 0) ? m_left->read(blockStart, lLen) : QByteArray();
        const QByteArray b = (rLen > 0) ? m_right->read(blockStart, rLen) : QByteArray();

        // 只有兩邊都完整讀到且整塊相等，才可以整塊跳過（這是穩定的關鍵）
        if (a.size() == len && b.size() == len &&
            std::memcmp(a.constData(), b.constData(), size_t(len)) == 0) {
            pos = blockStart - 1;
            continue;
        }

        // 不能跳過 → 從 pos 在此 block 的位置開始往前逐 byte（保證正確）
        qint64 i0 = pos - blockStart;
        if (i0 >= len) i0 = len - 1;

        for (qint64 i = i0; i >= 0; --i) {
            const qint64 cur = blockStart + i;

            const bool inL = (cur < ls);
            const bool inR = (cur < rs);
            if (inL != inR) { out = cur; return true; }

            const char av = (i < a.size()) ? a[int(i)] : 0;
            const char bv = (i < b.size()) ? b[int(i)] : 0;
            if (av != bv) { out = cur; return true; }
        }

        pos = blockStart - 1;
    }

    return false;
}
