#ifndef TEXTVIEWPORT_H
#define TEXTVIEWPORT_H

#pragma once

#include "../hexadecimal_editor/chunkslite.h"
#include "../hexadecimal_editor/overlaymap.h"

#include "lineindex.h"

#include <QAbstractScrollArea>
#include <QFontMetrics>
#include <QFutureWatcher>
#include <QLineEdit>
#include <QScrollBar>
#include <QToolButton>

class ChunksLite;
class OverlayMap;

class TextViewport : public QAbstractScrollArea
{
    Q_OBJECT
public:
    explicit TextViewport(QWidget* parent = nullptr);

    void setSource(ChunksLite* chunks, OverlayMap* overlay);

    void setFont(const QFont& f);

    void openSearchPanel();
    void findNext();
    void findPrev();
    void gotoLine(qint64 line);

signals:
    void progressStarted();
    void progressFinished();
    void findFinished(bool found, qint64 line, qint64 offset);

protected:
    void paintEvent(QPaintEvent* e) override;
    void resizeEvent(QResizeEvent* e) override;
    bool eventFilter(QObject* obj, QEvent* ev) override;

private slots:
    void updateScrollBar();
    void updateViewport();
    void paintLines(QPainter& p);
    qint64 findLineOffset(qint64 targetLine);

private:
    ChunksLite* m_chunks = nullptr;
    OverlayMap* m_overlay = nullptr;
    LineIndex* m_lineIndex = nullptr;

    QWidget*    m_searchPanel = nullptr;
    QLineEdit*  m_findEdit = nullptr;
    QToolButton* m_btnFindPrev = nullptr;
    QToolButton* m_btnFindNext = nullptr;
    QLineEdit*  m_gotoEdit = nullptr;
    QToolButton* m_btnGoto = nullptr;

    QFutureWatcher<qint64> m_lineCountWatcher;
    bool m_countingLines = false;

    void createSearchPanel();
    void startFindAsync(const QByteArray& pat, bool backwards);
    void resetFindState();

    // Find
    QFutureWatcher<QPair<qint64,qint64>> m_findWatcher;
    bool m_findRunning = false;
    // void startFindJob(const QByteArray& pat, qint64 startOffset, bool backwards);

    // 類似 HexView 的 lastFind
    qint64 m_lastFindOffset = -1;
    qint64 m_lastFindLine   = 0;

    // 命中視覺
    qint64 m_matchOffset = -1;
    int    m_matchLen    = 0;
    bool   m_caretOn     = true;
    QTimer* m_caretTimer = nullptr;

    QFont       m_font;
    QFontMetrics m_fm;

    int m_lineHeight = 0;
    int m_visibleLines = 0;

    qint64 m_totalLines = 0;   // M1 先粗算
};

#endif // TEXTVIEWPORT_H
