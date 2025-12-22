#ifndef OVERLAYMAP_H
#define OVERLAYMAP_H

#include "chunkslite.h"
#include <QByteArray>
#include <QVector>
#include <QtGlobal>

struct OverlaySegment {
    qint64 offset;     // 原始檔案中的位置
    QByteArray data;   // 覆寫 / 插入後的資料
    bool isInsert;     // true = insert, false = replace
};

// --- OverlayMap (piece table) ---
class OverlayMap {
public:
    struct Piece {
        enum class Src { Base, Add } src;     // Base 或 Add
        qint64 start;                         // base/add 裡的起點
        qint64 len;                           // 本段的長度
    };
    void reset(qint64 baseSize); // ⭐ loadDevice() 時呼叫一次

    QByteArray read(qint64 offset, qint64 len, ChunksLite *base);                           // 依 pieces 拼出邏輯資料
    void insert(qint64 offset, const QByteArray &data);                                     // 插入一段 Add pieces
    void erase(qint64 offset, qint64 len);                                                  // 移除範圍內的 pieces
    void replace(qint64 offset, const QByteArray &data, ChunksLite *base);                // 不改 size，只改內容
    QVector<Piece> eraseAndReturnPieces(qint64 offset, qint64 len);
    void insertPieces(qint64 offset, const QVector<Piece>& pieces);

    qint64 size() const;
    void clear();

private:
    QVector<Piece> m_pieces;
    QByteArray m_add; // 所有 insert/replace 的新資料都 append 進這裡
    qint64 m_baseSize = 0;

    void splitAt(qint64 pos);                 // 把 piece 切開
    int  findPieceIndex(qint64 pos) const;    // 找 pos 落在哪個 piece
    void mergeAdjacentPieces();
};
#endif // OVERLAYMAP_H
