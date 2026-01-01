#ifndef TABPROGRESSBAR_H
#define TABPROGRESSBAR_H

#include <QPaintEvent>
#include <QWidget>


class TabProgressBar : public QWidget
{
    Q_OBJECT
public:
    // explicit TabProgressBar(QWidget* parent = nullptr);

    // void start();
    // void setValue(int percent); // 0~100
    // void finish();

protected:
    void paintEvent(QPaintEvent*) override;

private:
    int m_value = 0;
};

#endif // TABPROGRESSBAR_H
