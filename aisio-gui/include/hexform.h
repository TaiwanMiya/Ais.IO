#ifndef HEXFORM_H
#define HEXFORM_H

#include "hexview.h"
#include <QPropertyAnimation>
#include <QWidget>

QT_BEGIN_NAMESPACE
namespace Ui { class HexForm; }
QT_END_NAMESPACE

class HexForm : public QWidget {
    Q_OBJECT

public:
    explicit HexForm(const QByteArray &arr = QByteArray(), QWidget *parent = nullptr, bool setEdit = true);
    ~HexForm();

protected:
    void resizeEvent(QResizeEvent *event) override;   // ⭐ 新增

private:
    Ui::HexForm *ui;
    HexView *m_hexView;

    enum class FindMode { Hex, Text };
    FindMode   m_findMode = FindMode::Hex;
    QByteArray m_lastPattern;
    qint64     m_lastPos = -1;  // 下次搜尋的起點

    void setupShortcuts();
    QByteArray parseHexString(const QString& s, bool *ok) const;
    qint64 doFind(bool backwards, bool newPattern);
    void EnabledConnect();
    void positionSearchBar();                         // ⭐ 新增

private slots:
    void onFindModeChanged(int index);
    void onFindTextEdited();
    void onFindNext();
    void onFindPrev();
    void onGotoOffset();
    void focusGotoBox();
    void toggleSearchBar(bool show);
};

#endif // HEXFORM_H
