#include "../include/hexform.h"
#include "../include/hexview.h"
#include "ui_hexform.h"

HexForm::HexForm(const QByteArray &arr, QWidget *parent, bool setEdit)
    : QWidget(parent)
    , ui(new Ui::HexForm)
{
    ui->setupUi(this);

    // ⭐ HexView 只放在 ui->hexViewWidget 裡
    m_hexView = new HexView(ui->hexViewWidget);
    m_hexView->setGeometry(ui->hexViewWidget->rect());
    m_hexView->show();

    m_hexView->loadData(arr);
    m_hexView->setEditable(setEdit);
}

HexForm::~HexForm()
{
    delete ui;
}

void HexForm::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);

    // 視窗大小改變 → 讓 HexView 填滿 hexViewWidget
    if (m_hexView)
        m_hexView->setGeometry(ui->hexViewWidget->rect());
}

void HexForm::showEvent(QShowEvent *event)
{
    QWidget::showEvent(event);

    if (m_hexView)
        m_hexView->setGeometry(ui->hexViewWidget->rect());
}
