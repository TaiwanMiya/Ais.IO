#include "tabprogressbar.h"
#include <QPainter>

void TabProgressBar::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.fillRect(rect(), QColor(40, 160, 255, 200));

    int w = rect().width() * m_value / 100;
    p.fillRect(0, 0, w, height(), QColor(90, 200, 255));
}
