#include "textview.h"

#include <QVBoxLayout>

TextView::TextView(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0,0,0,0);

    m_viewport = new TextViewport(this);
    layout->addWidget(m_viewport);

    connect(m_viewport, &TextViewport::progressStarted,
            this, &TextView::progressStarted);
    connect(m_viewport, &TextViewport::progressFinished,
            this, &TextView::progressFinished);
}

bool TextView::loadDevice(QIODevice* dev)
{
    if (!dev) return false;

    m_chunks.setDevice(dev);

    m_overlay.reset(m_chunks.size());
    m_overlay.setBase(&m_chunks);

    m_viewport->setSource(&m_chunks, &m_overlay);
    return true;
}

void TextView::openSearchPanel() {
    if (m_viewport)
        m_viewport->openSearchPanel();
}

void TextView::findNext() {
    if (m_viewport)
        m_viewport->findNext();
}

void TextView::findPrev() {
    if (m_viewport)
        m_viewport->findPrev();
}

void TextView::gotoLine(qint64 line) {
    if (!m_viewport)
        return;
    m_viewport->gotoLine(line);
}
