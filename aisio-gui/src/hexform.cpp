#include "../include/hexform.h"
#include "../include/hexview.h"
#include "ui_hexform.h"

#include <QFileDialog>
#include <QLineEdit>

HexForm::HexForm(QIODevice *dev, QWidget *parent, bool setEdit)
    : QMainWindow(parent)
    , ui(new Ui::HexForm) {
    ui->setupUi(this);
    m_hexView = new HexView(ui->hexViewWidget);
    this->createStatusBar();
    this->createAction();

    m_hexView->setGeometry(ui->hexViewWidget->rect());
    m_hexView->show();

    m_hexView->loadDevice(dev);
    m_hexView->setEditable(setEdit);
}

HexForm::~HexForm() {
    delete ui;
}

void HexForm::createStatusBar() {
    m_statusBar = statusBar();

    lbAddressName = new QLabel(tr("Address:"), this);
    lbAddress     = new QLineEdit(this);
    lbAddress->setMinimumWidth(90);
    lbAddress->setReadOnly(true);

    lbSizeName = new QLabel(tr("Size:"), this);
    lbSize     = new QLineEdit(this);
    lbSize->setMinimumWidth(120);
    lbSize->setReadOnly(true);

    m_statusBar->addPermanentWidget(lbAddressName);
    m_statusBar->addPermanentWidget(lbAddress);
    m_statusBar->addPermanentWidget(lbSizeName);
    m_statusBar->addPermanentWidget(lbSize);

    connect(m_hexView, &HexView::cursorChanged,
            this, &HexForm::setAddress);

    connect(m_hexView, &HexView::dataSizeChanged,
            this, &HexForm::setSize);

    m_statusBar->showMessage(tr("Ready"), 2000);
}

void HexForm::createAction() {
    connect(ui->actionOpen, SIGNAL(triggered()), this, SLOT(open()));
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

// ============SLOTS============

void HexForm::setAddress(qint64 address) {
    lbAddress->setText(QString("%1").arg(address, m_hexView->getaddressChars(), 16, QLatin1Char('0')).toUpper());
}

void HexForm::setSize(qint64 size) {
    lbSize->setText(QString("%1").arg(size, 1).toUpper());
}

void HexForm::open() {
    QString fileName = QFileDialog::getOpenFileName(this);
    if (!fileName.isEmpty()) {
        QFile *file = new QFile(fileName, this);
        m_hexView->loadDevice(file);
        m_hexView->setEditable(true);
        statusBar()->showMessage(tr("File loaded..."), 2000);
    }
}
