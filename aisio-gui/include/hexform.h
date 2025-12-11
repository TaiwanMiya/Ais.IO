#ifndef HEXFORM_H
#define HEXFORM_H

#include "hexview.h"
#include <QWidget>
#include <QShowEvent>

QT_BEGIN_NAMESPACE
namespace Ui { class HexForm; }
QT_END_NAMESPACE

class HexForm : public QWidget {
    Q_OBJECT

public:
    explicit HexForm(const QByteArray &arr = QByteArray(),
                     QWidget *parent = nullptr,
                     bool setEdit = true);
    ~HexForm();

protected:
    void resizeEvent(QResizeEvent *event) override;
    void showEvent(QShowEvent *event) override;

private:
    Ui::HexForm *ui;
    HexView     *m_hexView = nullptr;
};

#endif // HEXFORM_H
