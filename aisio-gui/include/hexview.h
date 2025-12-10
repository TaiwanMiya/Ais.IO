#ifndef HEXVIEW_H
#define HEXVIEW_H

#include <QAbstractScrollArea>
#include <QByteArray>
#include <QImage>
#include <QVector>
#include <QModelIndex>

class HexView : public QAbstractScrollArea
{
    Q_OBJECT
public:
    explicit HexView(QWidget *parent = nullptr);

    void loadData(const QByteArray &data);
    void setEditable(bool editable);

    // 給 HexForm / 外部使用的查詢 API
    qint64 findBytes(const QByteArray &pattern, qint64 start, bool backwards);
    void   gotoOffset(qint64 offset);
    qint64 offsetFromIndex(const QModelIndex &idx) const;
    QModelIndex currentIndex() const;
    qint64 currentOffset() const;

    const QByteArray &data() const { return m_data; }

protected:
    void paintEvent(QPaintEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void mouseReleaseEvent(QMouseEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;
    void wheelEvent(QWheelEvent *event) override;

    QSize sizeHint() const override;
    QSize minimumSizeHint() const override;

private:
    // 主要資料
    QByteArray m_data;
    bool       m_editable      = true;
    qint64     m_cursorOffset  = 0;   // 游標所在 byte
    qint64     m_baseOffset    = 0;   // 顯示位址 base（目前先 0）

    // 字體與度量
    int m_charWidth    = 0;
    int m_lineHeight   = 0;
    int m_bytesPerLine = 16;          // 會根據視窗寬度自動調整
    int m_leftMargin   = 12;
    int m_topMargin    = 4;

    // X 座標
    int m_hexStartX    = 0;
    int m_asciiStartX  = 0;
    int m_hexCellWidth = 0;

    // HEX / ASCII 字元快取（文字）
    QString m_hexCache[256];
    QChar   m_asciiCache[256];

    // === Selection Model ===
    qint64 m_selStart = -1;
    qint64 m_selEnd   = -1;
    qint64 m_selAnchor = -1;
    bool   m_dragSelecting = false;
    bool   m_showCursor = true;
    int    m_errorFlashCounter = 0;
    QTimer *m_errorFlashTimer = nullptr;

    // 工具方法
    void clearSelectionRange();
    void setSelectionRange(qint64 start, qint64 end);
    bool hasSelection() const { return m_selStart >= 0 && m_selEnd > m_selStart; }
    qint64 clickedOffset(const QPoint &p);

    // === Undo / Redo ===
    struct Edit {
        qint64 offset;
        quint8 oldByte;
        quint8 newByte;
    };
    QVector<Edit> m_undoStack;
    QVector<Edit> m_redoStack;

    void pushEdit(qint64 offset, quint8 oldByte, quint8 newByte);
    void undo();
    void redo();

    // === Internal helper ===
    void updateSelectionAfterCursorMove();

    // 每行的影像快取（行快取）
    struct LineCacheEntry {
        int   line  = -1;     // 第幾行
        bool  valid = false;
        QImage image;
    };
    QVector<LineCacheEntry> m_lineCache;
    int m_nextCacheSlot = 0;  // 簡單輪替（LRU 近似）

    // === Multi-selection support ===
    struct Range {
        qint64 start;
        qint64 end;   // end is exclusive
    };
    QVector<Range> m_extraSelections;

    bool byteInAnySelection(qint64 off) const;
    QVector<Range> allSelectionsNormalized() const;

    // === Clipboard support ===
    void copySelectionToClipboard();
    void pasteFromClipboard();

    enum class Area { None, Hex, Ascii };
    Area lastClickArea = Area::None;

    // 設定
    int addressChars() const { return 8; } // 8 位位址（00000000~FFFFFFFF）

    void updateMetrics();                    // 更新度量 + bytesPerLine + X 座標
    void updateScrollBars();                 // 根據資料與度量更新捲軸範圍
    void recalcBytesPerLineForWidth(int viewportWidth);
    void ensureVisible(qint64 offset);
    void invalidateAllLines();

    // 行快取相關
    void ensureLineCacheCapacity();          // 依視窗高度調整快取大小
    const QImage &getLineImage(int line);    // 取得指定行的影像（必要時重畫）
    QImage renderLineToImage(int line);      // 真正畫一行內容到 QImage

    // 游標與編輯
    void moveCursorRelative(qint64 deltaBytes);
    void moveCursorLineRelative(qint64 deltaLines);
    void moveCursorToLineStart();
    void moveCursorToLineEnd();
    bool handleHexEdit(QKeyEvent *event);
    bool handleAsciiEdit(QKeyEvent *event);
    void flashError();
};

#endif // HEXVIEW_H
