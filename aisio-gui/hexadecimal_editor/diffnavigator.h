#ifndef DIFFNAVIGATOR_H
#define DIFFNAVIGATOR_H

#include <QtGlobal>

class OverlayMap;
class DiffNavigator
{
public:
    void setSources(OverlayMap* left,
                    OverlayMap* right);

    qint64 size() const;

    bool findNext(qint64 fromOffset, qint64& outOffset);
    bool findPrev(qint64 fromOffset, qint64& outOffset);

private:
    bool scanForward(qint64 start, qint64& out);
    bool scanBackward(qint64 start, qint64& out);

    OverlayMap* m_left  = nullptr;
    OverlayMap* m_right = nullptr;

    static constexpr qint64 CHUNK = 0x10000; // 64KB
};

#endif // DIFFNAVIGATOR_H
