#include "../include/overlaymap.h"

void OverlayMap::reset(qint64 baseSize)
{
    m_baseSize = baseSize;
    m_pieces.clear();
    m_add.clear();
    if (m_baseSize > 0)
        m_pieces.push_back(Piece{Piece::Src::Base, 0, m_baseSize});
}

void OverlayMap::clear()
{
    m_pieces.clear();
    m_add.clear();
}

qint64 OverlayMap::size() const
{
    qint64 total = 0;
    for (const auto &p : m_pieces) total += p.len;
    return total;
}

int OverlayMap::findPieceIndex(qint64 pos) const
{
    if (pos <= 0) return 0;
    qint64 cur = 0;
    for (int i = 0; i < m_pieces.size(); ++i) {
        qint64 next = cur + m_pieces[i].len;
        if (pos < next) return i;
        cur = next;
    }
    return m_pieces.size(); // end
}

void OverlayMap::splitAt(qint64 pos)
{
    if (pos <= 0) return;
    qint64 cur = 0;
    for (int i = 0; i < m_pieces.size(); ++i) {
        Piece p = m_pieces[i];
        qint64 next = cur + p.len;
        if (pos == cur || pos == next) return;      // already boundary
        if (pos > cur && pos < next) {
            // split p into [cur..pos) and [pos..next)
            qint64 leftLen  = pos - cur;
            qint64 rightLen = next - pos;

            Piece left = p;
            left.len = leftLen;

            Piece right = p;
            right.start = p.start + leftLen;
            right.len = rightLen;

            m_pieces[i] = left;
            m_pieces.insert(i + 1, right);
            return;
        }
        cur = next;
    }
}

QByteArray OverlayMap::read(qint64 offset, qint64 len, ChunksLite *base)
{
    QByteArray out;
    if (len <= 0 || offset < 0) return out;

    qint64 logicalSize = size();
    if (offset >= logicalSize) return out;
    if (offset + len > logicalSize) len = logicalSize - offset;

    qint64 curPos = 0;
    for (const auto &p : m_pieces) {
        if (len <= 0) break;

        qint64 pieceStart = curPos;
        qint64 pieceEnd   = curPos + p.len;

        if (pieceEnd <= offset) { curPos = pieceEnd; continue; }

        qint64 takeStart = qMax(offset, pieceStart);
        qint64 takeEnd   = qMin(pieceEnd, offset + len);
        qint64 takeLen   = takeEnd - takeStart;
        qint64 insideOff = takeStart - pieceStart;

        if (takeLen > 0) {
            if (p.src == Piece::Src::Base) {
                if (base) out += base->read(p.start + insideOff, takeLen);
            } else {
                out += m_add.mid(int(p.start + insideOff), int(takeLen));
            }
            len -= takeLen;
            offset = takeEnd;
        }

        curPos = pieceEnd;
    }
    return out;
}

void OverlayMap::insert(qint64 offset, const QByteArray &data)
{
    if (data.isEmpty())
        return;

    // clamp offset to [0, size]
    qint64 total = size();
    if (offset < 0) offset = 0;
    if (offset > total) offset = total;

    // append inserted data to add buffer (stable storage)
    qint64 addStart = m_add.size();
    m_add += data;

    Piece inserted{Piece::Src::Add, addStart, (qint64)data.size()};

    QVector<Piece> newPieces;
    newPieces.reserve(m_pieces.size() + 1);

    // Rebuild pieces by logical position (no findPieceIndex / splitAt / cur-dependent mutations)
    qint64 pos = 0;
    bool insertedDone = false;

    for (const Piece &p : m_pieces) {
        qint64 pStart = pos;
        qint64 pEnd   = pos + p.len;

        if (!insertedDone) {
            // Insert happens before current piece
            if (offset <= pStart) {
                newPieces.push_back(inserted);
                insertedDone = true;
            }
            // Insert happens inside current piece → split into left + inserted + right
            else if (offset > pStart && offset < pEnd) {
                qint64 leftLen = offset - pStart;
                qint64 rightLen = pEnd - offset;

                if (leftLen > 0) {
                    Piece left = p;
                    left.len = leftLen;
                    newPieces.push_back(left);
                }

                newPieces.push_back(inserted);
                insertedDone = true;

                if (rightLen > 0) {
                    Piece right = p;
                    right.start += leftLen;
                    right.len = rightLen;
                    newPieces.push_back(right);
                }

                pos = pEnd;
                continue; // already handled this piece via split
            }
        }

        // Normal: keep original piece
        newPieces.push_back(p);
        pos = pEnd;
    }

    // Insert at end (offset == total)
    if (!insertedDone) {
        newPieces.push_back(inserted);
    }

    m_pieces.swap(newPieces);
}

void OverlayMap::erase(qint64 offset, qint64 len)
{
    if (len <= 0 || m_pieces.isEmpty())
        return;

    qint64 end = offset + len;

    QVector<Piece> newPieces;
    newPieces.reserve(m_pieces.size());

    qint64 pos = 0; // 邏輯檔案中的起始位置

    for (const Piece &p : m_pieces) {
        qint64 pStart = pos;
        qint64 pEnd   = pos + p.len;

        // Case 1：整個 piece 在刪除區間外 → 原封不動保留
        if (pEnd <= offset || pStart >= end) {
            newPieces.push_back(p);
        }
        else {
            // Case 2：有重疊，需要切割
            // 前段（保留）
            if (pStart < offset) {
                Piece left = p;
                left.len = offset - pStart;
                newPieces.push_back(left);
            }

            // 中段：被刪除（直接略過，不加入）

            // 後段（保留）
            if (pEnd > end) {
                Piece right = p;
                right.start += (end - pStart);
                right.len = pEnd - end;
                newPieces.push_back(right);
            }
        }

        pos = pEnd;
    }

    m_pieces.swap(newPieces);
}

void OverlayMap::replace(qint64 offset, const QByteArray &data, ChunksLite *base)
{
    if (data.isEmpty()) return;

    // 確保 piece 邊界正確
    splitAt(offset);
    splitAt(offset + data.size());

    qint64 cur = 0;
    int di = 0;

    for (int i = 0; i < m_pieces.size() && di < data.size(); ++i) {
        Piece &p = m_pieces[i];
        qint64 next = cur + p.len;

        if (next <= offset) {
            cur = next;
            continue;
        }

        qint64 start = qMax(offset, cur);
        qint64 end   = qMin(next, offset + data.size());
        qint64 len   = end - start;
        qint64 inside = start - cur;

        if (p.src == Piece::Src::Base) {
            // Base → 轉成 Add piece（只一次）
            QByteArray old = base->read(p.start + inside, len);
            qint64 addStart = m_add.size();
            m_add += data.mid(di, len);

            p.src   = Piece::Src::Add;
            p.start = addStart;
            p.len   = len;
        } else {
            // Add → 直接覆寫 m_add（關鍵！）
            memcpy(m_add.data() + p.start + inside,
                   data.constData() + di,
                   size_t(len));
        }

        di += len;
        cur = next;
    }
    mergeAdjacentPieces();
}

void OverlayMap::mergeAdjacentPieces()
{
    if (m_pieces.isEmpty())
        return;

    QVector<Piece> merged;
    merged.reserve(m_pieces.size());

    Piece cur = m_pieces[0];

    for (int i = 1; i < m_pieces.size(); ++i) {
        const Piece &p = m_pieces[i];

        // 同來源、且在 buffer 中是連續的 → 合併
        if (p.src == cur.src &&
            cur.start + cur.len == p.start)
        {
            cur.len += p.len;
        }
        else {
            merged.push_back(cur);
            cur = p;
        }
    }
    merged.push_back(cur);

    m_pieces.swap(merged);
}
