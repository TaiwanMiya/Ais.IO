#ifndef MSGBOX_H
#define MSGBOX_H

#include <QMessageBox>


class MsgBox : public QMessageBox {
    Q_OBJECT
public:
    explicit MsgBox(QWidget *parent = nullptr, QMessageBox::Icon icon = QMessageBox::Icon::NoIcon);
    ~MsgBox();
    void show(const QString title, const QString text);
};

#endif // MSGBOX_H
