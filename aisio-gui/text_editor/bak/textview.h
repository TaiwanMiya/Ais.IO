#ifndef TEXTVIEW_H
#define TEXTVIEW_H

#pragma once

#include "textviewport.h"


class TextView : public QWidget
{
    Q_OBJECT
public:
    explicit TextView(QWidget* parent = nullptr);

    bool loadDevice(QIODevice* dev);

    void openSearchPanel();
    void findNext();
    void findPrev();
    void gotoLine(qint64 line);

private:
    TextViewport* m_viewport = nullptr;

    ChunksLite    m_chunks;
    OverlayMap    m_overlay;
};


#endif // CODEEDITOR_H
