#include "hexdiffwidget.h"
#include "hexview.h"

#include <QSplitter>
#include <QHBoxLayout>

HexDiffWidget::HexDiffWidget(QWidget *parent)
    : QWidget(parent)
{
    m_splitter = new QSplitter(Qt::Horizontal, this);

    m_left  = new HexView(m_splitter);
    m_right = new HexView(m_splitter);

    // 初期等分
    m_splitter->setStretchFactor(0, 1);
    m_splitter->setStretchFactor(1, 1);

    auto *layout = new QHBoxLayout(this);
    layout->setContentsMargins(0,0,0,0);
    layout->addWidget(m_splitter);

    m_left->setDiffNavSources(&m_left->overlay(), &m_right->overlay());
    m_right->setDiffNavSources(&m_left->overlay(), &m_right->overlay());

    connect(m_left,  &HexView::cursorChanged, this, &HexDiffWidget::onLeftCursorChanged);
    connect(m_right, &HexView::cursorChanged, this, &HexDiffWidget::onRightCursorChanged);
    connect(m_left,  &HexView::diffFound,     this, &HexDiffWidget::onDiffFound);
    connect(m_right, &HexView::diffFound,     this, &HexDiffWidget::onDiffFound);
}

void HexDiffWidget::rebuildDiff()
{
    if (!m_left || !m_right) return;

    // Compare *logical* size (OverlayMap), not base file size.
    m_sizeA = m_left->overlay().size();
    m_sizeB = m_right->overlay().size();
}

HexView* HexDiffWidget::leftView() const  { return m_left; }
HexView* HexDiffWidget::rightView() const { return m_right; }

void HexDiffWidget::onLeftCursorChanged(qint64 off)
{
    if (m_inDiffFlash) return;
    if (m_syncingCursor) return;
    m_syncingCursor = true;
    m_right->setCursorOffsetExternal(off);
    m_syncingCursor = false;
}

void HexDiffWidget::onRightCursorChanged(qint64 off)
{
    if (m_inDiffFlash) return;
    if (m_syncingCursor) return;
    m_syncingCursor = true;
    m_left->setCursorOffsetExternal(off);
    m_syncingCursor = false;
}

void HexDiffWidget::onDiffFound(qint64 offset)
{
    if (m_inDiffFlash)
        return;

    m_inDiffFlash = true;

    // 左右 view 同步閃爍
    m_left->startDiffFlash(offset);
    m_right->startDiffFlash(offset);

    m_inDiffFlash = false;
}
