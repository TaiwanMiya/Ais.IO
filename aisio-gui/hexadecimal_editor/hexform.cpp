#include "hexform.h"
#include "hexview.h"
#include "ui_hexform.h"

#include <QFileDialog>
#include <QLineEdit>
#include <QMessageBox>

HexForm::HexForm(QIODevice *dev, QWidget *parent, bool setEdit)
    : QMainWindow(parent)
    , ui(new Ui::HexForm) {
    ui->setupUi(this);
    m_hexView = new HexView(ui->hexViewWidget);
    this->createStatusBar();
    this->createAction();

    isUntitled = true;
    isModified = false;

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
    lineEditAddress     = new QLineEdit(this);
    lineEditAddress->setMinimumWidth(90);
    lineEditAddress->setMaximumWidth(120);
    lineEditAddress->setReadOnly(true);

    lbSizeName = new QLabel(tr("Size:"), this);
    lineEditSize     = new QLineEdit(this);
    lineEditSize->setMinimumWidth(120);
    lineEditSize->setMaximumWidth(150);
    lineEditSize->setReadOnly(true);

    m_statusBar->addPermanentWidget(lbAddressName);
    m_statusBar->addPermanentWidget(lineEditAddress);
    m_statusBar->addPermanentWidget(lbSizeName);
    m_statusBar->addPermanentWidget(lineEditSize);

    connect(m_hexView, &HexView::cursorChanged,
            this, &HexForm::setAddress);

    connect(m_hexView, &HexView::dataSizeChanged,
            this, &HexForm::setSize);

    m_statusBar->showMessage(tr("Ready"), 2000);
}

void HexForm::createAction() {
    connect(ui->actionOpen, SIGNAL(triggered()), this, SLOT(open()));
    connect(ui->actionSave, SIGNAL(triggered()), this, SLOT(save()));
    connect(ui->actionSave_As, SIGNAL(triggered()), this, SLOT(saveAs()));
    connect(m_hexView, SIGNAL(dataChanged()), this, SLOT(dataChanged()));
}

void HexForm::setCurrentFile(const QString &fileName) {
    curFile = QFileInfo(fileName).canonicalFilePath();
    isUntitled = fileName.isEmpty();
    setWindowModified(false);
    if (fileName.isEmpty())
        setWindowFilePath("Hexadecimal Editor");
    else
        setWindowFilePath(curFile + " - Hexadecimal Editor");
}

bool HexForm::saveFile(const QString &fileName) {
    QString tmpFileName = fileName + ".~tmp";

    QApplication::setOverrideCursor(Qt::WaitCursor);
    QFile file(tmpFileName);
    bool ok = m_hexView->saveToFile(tmpFileName);
    if (QFile::exists(fileName))
        ok = QFile::remove(fileName);
    if (ok)
    {
        file.setFileName(tmpFileName);
        ok = file.copy(fileName);
        if (ok) {
            ok = QFile::remove(tmpFileName);
            isModified = false;
            setWindowModified(false);
        }
    }
    QApplication::restoreOverrideCursor();

    if (!ok) {
        QMessageBox box(this);
        box.setIcon(QMessageBox::Critical);
        box.setWindowTitle(tr("Save failed"));
        box.setText(tr("Cannot write file %1.").arg(fileName));
        box.setStyleSheet("* { background:#222222; color:#f0f0f0; }");
        box.exec();
        return false;
    }

    setCurrentFile(fileName);
    statusBar()->showMessage(tr("File saved"), 2000);
    return true;
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
    lineEditAddress->setText(QString("%1").arg(address, m_hexView->getaddressChars(), 16, QLatin1Char('0')).toUpper());
}

void HexForm::setSize(qint64 size) {
    lineEditSize->setText(QString("%1").arg(size, 1).toUpper());
}

void HexForm::open() {
    QString fileName = QFileDialog::getOpenFileName(this);
    if (!fileName.isEmpty()) {
        QFile *file = new QFile(fileName, this);
        m_hexView->loadDevice(file);
        m_hexView->setEditable(true);
        setCurrentFile(fileName);
        statusBar()->showMessage(tr("File loaded..."), 2000);
    }
}

bool HexForm::save() {
    if (isUntitled) {
        return saveAs();
    } else {
        return saveFile(curFile);
    }
}

bool HexForm::saveAs() {
    QString fileName = QFileDialog::getSaveFileName(this, tr("Save As"),
                                                    curFile);
    if (fileName.isEmpty())
        return false;

    return saveFile(fileName);
}

void HexForm::dataChanged() {
    isModified = true;
    setWindowModified(isModified);
}
