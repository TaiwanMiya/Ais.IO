#ifndef HEXVIEW_H
#define HEXVIEW_H

#include <QAbstractScrollArea>
#include <QByteArray>
#include <QModelIndex>

class HexView : public QAbstractScrollArea
{
    Q_OBJECT
public:
    explicit HexView(QWidget *parent = nullptr);

    void loadData(const QByteArray &data);
    void setEditable(bool editable);

    // 給 HexForm 用的 API
    qint64 findBytes(const QByteArray &pattern, qint64 start, bool backwards);
    void gotoOffset(qint64 offset);
    qint64 offsetFromIndex(const QModelIndex &idx) const;
    QModelIndex currentIndex() const;
    qint64 currentOffset() const;

    const QByteArray &data() const { return m_data; }

protected:
    void paintEvent(QPaintEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;
    void wheelEvent(QWheelEvent *event) override;

private:
    QByteArray m_data;
    bool      m_editable = true;

    // 游標是「第幾個 byte」
    qint64    m_cursorOffset = 0;
    qint64    m_baseOffset   = 0;   // 顯示用位址 base（目前先 0）

    // 字體與度量
    int       m_charWidth    = 0;
    int       m_lineHeight   = 0;
    int       m_bytesPerLine = 16;

    int       m_leftMargin   = 12;
    int       m_topMargin    = 4;

    // 預先算好的座標
    int m_hexStartX = 0;
    int m_asciiStartX = 0;
    int m_hexCellWidth = 0;

    // HEX / ASCII 快取
    QString m_hexCache[256];
    QChar   m_asciiCache[256];

    // 快速計算
    int       addressChars() const { return 8; } // 8 位 hex 地址

    void updateMetrics();
    void updateScrollBars();
    void ensureVisible(qint64 offset);

    void moveCursorRelative(qint64 deltaBytes);
    void moveCursorLineRelative(qint64 deltaLines);
    void moveCursorToLineStart();
    void moveCursorToLineEnd();

    void handleHexEdit(QKeyEvent *event);
};

#endif // HEXVIEW_H
