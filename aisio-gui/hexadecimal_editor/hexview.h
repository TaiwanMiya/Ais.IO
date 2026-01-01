#ifndef HEXVIEW_H
#define HEXVIEW_H

#include "chunkslite.h"
#include "diffnavigator.h"
#include "overlaymap.h"
#include <QString>
#include <QAbstractScrollArea>
#include <QByteArray>
#include <QImage>
#include <QVector>
#include <QModelIndex>
#include <QComboBox>
#include <QToolButton>
#include <QLineEdit>
#include <QTableWidgetItem>
#include <QFuture>
#include <QFutureWatcher>
#include <QtConcurrent>

class QLineEdit;
class QToolButton;
class QWidget;
class QTimer;
class QTableWidget;
class QComboBox;

struct HexViewStatus {
    qint64 cursorOffset   = -1;
    qint64 fileSize       = 0;
    qint64 selStart       = -1;
    qint64 selEnd         = -1;
    bool   hasSelection   = false;
    bool   isModified     = false;
    bool   inDiffSearch   = false;
    bool   inFindSearch   = false;
    QString mode;   // "HEX" / "ASCII"
    QString message;
};
Q_DECLARE_METATYPE(HexViewStatus)

class HexView : public QAbstractScrollArea
{
    Q_OBJECT
public:
    explicit HexView(QWidget *parent = nullptr);

    void loadDevice(QIODevice *dev);
    void setEditable(bool editable);

    // 給外部使用的 API
    qint64 findBytes(const QByteArray &pattern, qint64 start, bool backwards);
    void   onGotoOffset(qint64 offset);
    qint64 offsetFromIndex(const QModelIndex &idx) const;
    QModelIndex currentIndex() const;
    qint64 currentOffset() const;
    qint64 getBytesLength() const;
    qint64 getBaseBytesLength() const;
    QByteArray readBytes(qint64 offset, qint64 len) const;
    QByteArray readBaseBytes(qint64 offset, qint64 len) const;
    bool saveToFile(const QString &fileName);
    void setCursorOffsetExternal(qint64 off);
    int getaddressChars() { return addressChars(); }

    // diff/overlay 類視覺狀態改變時，需要把 line image cache 清掉
    void invalidateLineCache();
    OverlayMap& overlay();            // ⭐ 給 HexDiffWidget 用
    const OverlayMap& overlay() const;
    ChunksLite* chunks();
    const ChunksLite* chunks() const;

    // 設定
    enum class FindMode { Hex, Text };

    void   setFindMode(FindMode mode);
    void   resetFindState();

    void   undo();
    void   redo();
    void   copySelectionToClipboard();
    void   pasteFromClipboard();
    void   openInterpretPanel();

    void   openSearchPanel();
    void   findNext();
    void   findPrev();
    void   gotoOffset();

    void   diffFindNext();
    void   diffFindPrev();
    void   startDiffFlash(qint64 offset);
    void   diffClose();

    void invalidateAllLines();

    void setDiffNavSources(OverlayMap* left, OverlayMap* right);

signals:
    void cursorChanged(qint64 offset);
    void dataSizeChanged(qint64 size);
    void modifiedChanged(bool modified);
    void diffFound(qint64 pos);
    void viewScrolledToOffset(qint64 offset);
    void statusChanged(const HexViewStatus& status);
    void diffStarted();
    void diffFinished();

protected:
    void paintEvent(QPaintEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void mouseReleaseEvent(QMouseEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;
    void wheelEvent(QWheelEvent *event) override;
    bool eventFilter(QObject *obj, QEvent *ev) override;

    QSize sizeHint() const override;
    QSize minimumSizeHint() const override;

private:
    // 主要資料
    ChunksLite *m_chunks = nullptr;
    qint64     m_dataSize = 0;
    bool       m_editable      = true;
    qint64     m_cursorOffset  = 0;   // 游標所在 byte
    qint64     m_baseOffset    = 0;   // 顯示位址 base（目前先 0）
    bool       m_isModified = false;  // 是否已編輯
    OverlayMap m_overlay;

    // 刻度
    qint64 scrollResolution() const;

    // 字體與度量
    int m_charWidth    = 0;
    int m_lineHeight   = 0;
    int m_bytesPerLine = 16;          // 一行顯示幾個 byte (16)
    int m_leftMargin   = 12;
    int m_topMargin    = 4;

    // X 座標
    int m_hexStartX    = 0;
    int m_asciiStartX  = 0;
    int m_hexCellWidth = 0;

    // 閃爍
    int m_editFlashCounter = 0;
    int m_searchFlashCounter = 0;
    int m_diffFlashCounter = 0;
    int    m_errorFlashCounter = 0;
    QTimer *m_errorFlashTimer = nullptr;

    // HEX / ASCII 字元快取（文字）
    QString m_hexCache[256];
    QChar   m_asciiCache[256];

    // === Selection Model ===
    qint64 m_selStart = -1;
    qint64 m_selEnd   = -1;
    qint64 m_selAnchor = -1;
    bool   m_dragSelecting = false;
    bool   m_showCursor = true;
    bool   m_hexHighNibble = true;
    bool   m_mouseSelecting = false;

    // 工具方法
    void clearSelectionRange();
    void setSelectionRange(qint64 start, qint64 end);
    bool hasSelection() const { return m_selStart >= 0 && m_selEnd > m_selStart; }
    qint64 clickedOffset(const QPoint &p);

    // === Undo / Redo ===
    struct Edit {
        enum class Type {
            Replace,   // 單 byte 改值（你原本的）
            Insert,    // 插入 bytes
            Delete     // 刪除 bytes
        };

        Type type;              // Replace / Insert / Delete
        qint64 offset;          // 操作發生的位置 (before)
        QByteArray oldData;     // undo 用
        QByteArray newData;     // redo 用
        QVector<OverlayMap::Piece> pieces;      // Delete 用：被刪掉的 pieces
        qint64 deleteLen = 0;                   // Delete 用：redo 時要刪多長
        qint64 beforeLen = 0; // undo 完後，要選取的長度
        qint64 afterLen  = 0; // redo 完後，要選取的長度
    };
    QVector<Edit> m_undoStack;
    QVector<Edit> m_redoStack;
    int m_cleanUndoDepth = 0;  // 代表「未修改」時 undoStack 的深度（load/save 時更新）

    // ===== Edit helpers =====
    void pushEdit(Edit::Type type, qint64 offset, const QByteArray &oldData, const QByteArray &newData);
    void pushReplaceByte(qint64 offset, uchar oldByte, uchar newByte);
    void pushInsertBytes(qint64 offset, const QByteArray &data);
    void pushDeletePieces(qint64 offset, const QVector<OverlayMap::Piece>& pieces, qint64 deleteLen);
    void refreshModifiedFlag();

    // === Find / Search 狀態 ===
    FindMode   m_findMode    = FindMode::Hex;
    QByteArray m_lastPattern;
    qint64     m_lastPos     = -1;   // 下次搜尋起點（方向決定）
    qint64 onFindNext(const QString &input);
    qint64 onFindPrev(const QString &input);
    qint64 onGotoOffsetFromText(const QString &text);

    // 內部搜尋 helper
    QByteArray parseHexString(const QString& s, bool *ok) const;
    qint64     doFindInternal(const QString &input, bool backwards);

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

    // 選取
    void selectAll();

    // === Clipboard support ===
    enum class PasteMode { Insert, Overwrite };

    enum class Area { None, Hex, Ascii };
    Area lastClickArea = Area::None;

    // 刪除
    void deleteRanges(const QVector<Range> &ranges);

    // === 浮動搜尋面板 ===
    QWidget     *m_searchPanel   = nullptr;
    QLineEdit   *m_findEdit      = nullptr;
    QComboBox   *m_findModeCombo = nullptr;
    QToolButton *m_btnFindNext   = nullptr;
    QToolButton *m_btnFindPrev   = nullptr;
    QLineEdit   *m_gotoEdit      = nullptr;
    QToolButton *m_btnGoto       = nullptr;

    QPoint m_dragOffset;
    bool   m_dragSearchPanel = false;
    void createSearchPanel();
    void positionSearchPanel();
    void setupSearchShortcuts();

    // === Interpret As 面板 ===
    QWidget      *m_interpretPanel     = nullptr;
    QTableWidget *m_interpretTable     = nullptr;
    QToolButton  *m_btnInterpretClose  = nullptr;

    // Endian 切換
    QComboBox    *m_endianCombo        = nullptr;
    bool          m_interpretBigEndian = false;

    QPoint m_dragInterpretOffset;
    bool   m_dragInterpretPanel = false;
    bool   m_interpretUpdating = false;

    void createInterpretPanel();
    void positionInterpretPanel();
    void setupInterpretShortcuts();
    void updateInterpretPanel();
    void interpretApplyBytes(qint64 pos, int oldLen, const QByteArray& newBytes);
    QString interpretRawText(QTableWidgetItem* it) const;
    QByteArray bytesForInterpret(int maxLen) const;

    // 設定
    int addressChars() const; // 8 位位址（00000000~FFFFFFFF）
    qint64 visibleLineCount() const;
    void updateMetrics();                    // 更新度量 + bytesPerLine + X 座標
    void updateScrollBars();                 // 根據資料與度量更新捲軸範圍
    void recalcBytesPerLineForWidth(int viewportWidth);
    void ensureVisible(qint64 offset);
    void emitStatus(QString message = "");

    // 行快取相關
    void ensureLineCacheCapacity();          // 依視窗高度調整快取大小
    const QImage &getLineImage(int line);    // 取得指定行的影像（必要時重畫）
    QImage renderLineToImage(int line);      // 真正畫一行內容到 QImage

    // --- LineEdit flash support ---
    QTimer *m_lineEditFlashTimer = nullptr;
    int m_lineEditFlashCount = 0;
    QLineEdit *m_lineEditFlashing = nullptr;
    QString m_lineEditOriginalStyle;
    void flashLineEditError(QLineEdit *edit);

    // 游標與編輯
    qint64 lineFromScroll() const;
    void scrollToLine(qint64 line);
    void moveCursorRelative(qint64 deltaBytes);
    void moveCursorLineRelative(qint64 deltaLines);
    void moveCursorToLineStart();
    void moveCursorToLineEnd();
    bool handleHexEdit(QKeyEvent *event);
    bool handleAsciiEdit(QKeyEvent *event);
    void moveCursorToStart();
    void moveCursorToEnd();
    bool isHexString(const QString &s);

    // 閃爍
    void flashError();
    void flashEditError();
    void flashSearchError();
    void flashDiffError();

    // 比對
    DiffNavigator m_diffNav;
    qint64 m_lastDiffPos = -1;
    bool   m_hasLastDiff = false;
    QFutureWatcher<qint64> m_diffWatcher;
    bool m_diffRunning = false;

    qint64 effectiveSize() const {
        if (!m_chunks) return 0;
        return m_overlay.size();
    }

    // 游標合法化方法
    void clampCursorToValidRange() {
        qint64 sz = effectiveSize();
        if (sz <= 0) { m_cursorOffset = 0; return; }
        if (m_cursorOffset < 0) m_cursorOffset = 0;
        if (m_cursorOffset >= sz) m_cursorOffset = sz - 1;
    }

private slots:
    void onInterpretItemEdited(QTableWidgetItem *item);
};

#endif // HEXVIEW_H
