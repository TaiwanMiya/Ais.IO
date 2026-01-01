#ifndef HEXDIFFWIDGET_H
#define HEXDIFFWIDGET_H

#include <QWidget>

class QSplitter;
class HexView;

class HexDiffWidget : public QWidget
{
    Q_OBJECT
public:
    explicit HexDiffWidget(QWidget *parent = nullptr);

    void rebuildDiff();

    HexView* leftView() const;
    HexView* rightView() const;

private slots:
    void onLeftCursorChanged(qint64 off);
    void onRightCursorChanged(qint64 off);
    void onDiffFound(qint64 offset);

private:
    QSplitter *m_splitter = nullptr;
    HexView   *m_left     = nullptr;
    HexView   *m_right    = nullptr;
    bool      m_syncingCursor = false;
    bool      m_inDiffFlash = false;

    // --- incremental diff (avoid UI freeze on big files) ---
    bool   m_diffPending = false;

    qint64 m_sizeA   = 0;
    qint64 m_sizeB   = 0;
};

#endif // HEXDIFFWIDGET_H
