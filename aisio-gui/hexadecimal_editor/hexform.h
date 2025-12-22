#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "hexview.h"
#include <QMainWindow>
#include <QWidget>
#include <QShowEvent>
#include <QLabel>
#include <QStatusBar>

QT_BEGIN_NAMESPACE
namespace Ui { class HexForm; }
QT_END_NAMESPACE

class HexForm : public QMainWindow {
    Q_OBJECT

public:
    explicit HexForm(QIODevice *dev, QWidget *parent = nullptr, bool setEdit = true);
    ~HexForm();

protected:
    void resizeEvent(QResizeEvent *event) override;
    void showEvent(QShowEvent *event) override;

private slots:
    void setAddress(qint64 address);
    void setSize(qint64 address);
    void open();
    bool save();
    bool saveAs();
    void dataChanged();
    void shortcutKeyHelper();

private:
    Ui::HexForm *ui;
    HexView     *m_hexView      = nullptr;
    QStatusBar  *m_statusBar    = nullptr;
    QLabel *lbAddressName       = nullptr;
    QLineEdit *lineEditAddress  = nullptr;
    QLabel *lbSizeName          = nullptr;
    QLineEdit *lineEditSize     = nullptr;

    QString curFile;
    bool isUntitled;
    bool isModified;

    void createStatusBar();
    void createAction();

    void setCurrentFile(const QString &fileName);
    bool saveFile(const QString &fileName);
};

#endif // MAINWINDOW_H
