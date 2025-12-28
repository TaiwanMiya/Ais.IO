#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "hexview.h"
#include <QMainWindow>
#include <QWidget>
#include <QShowEvent>
#include <QLabel>
#include <QStatusBar>
#include <QTabWidget>
#include <QMetaObject>
#include <QDragEnterEvent>
#include <QDropEvent>

QT_BEGIN_NAMESPACE
namespace Ui { class HexForm; }
QT_END_NAMESPACE

class HexForm : public QMainWindow {
    Q_OBJECT

public:
    explicit HexForm(QWidget *parent = nullptr);
    ~HexForm();

protected:
    void resizeEvent(QResizeEvent *event) override;
    void showEvent(QShowEvent *event) override;

    // 拖曳開檔
    void dragEnterEvent(QDragEnterEvent *event) override;
    void dropEvent(QDropEvent *event) override;

private slots:
    void setAddress(qint64 address);
    void setSize(qint64 address);
    void create();
    void open();
    bool save();
    bool saveAs();
    void dataChanged();
    void shortcutKeyHelper();

private:
    Ui::HexForm *ui;
    QTabWidget  *m_tabs         = nullptr;
    QStatusBar  *m_statusBar    = nullptr;
    QLabel *lbAddressName       = nullptr;
    QLineEdit *lineEditAddress  = nullptr;
    QLabel *lbSizeName          = nullptr;
    QLineEdit *lineEditSize     = nullptr;
    QComboBox *cbSizeUnit       = nullptr;

    // tab 綁定的檔案資訊都存放在 page widget 的 dynamic property
    //  - "curFile"    : QString
    //  - "isUntitled" : bool
    //  - "isModified" : bool

    bool m_isClosingTab = false;

    // 目前連到 statusbar 的 view 訊號（切 tab 時要換綁定）
    QMetaObject::Connection m_connCursor;
    QMetaObject::Connection m_connSize;

    void createStatusBar();
    void createAction();
    void setupShortcuts();

    // tab helpers
    HexView* currentHexView() const;
    QWidget* currentPage() const;
    void attachStatusToView(HexView* view);

    int  addHexTab(QIODevice* dev, const QString& fileName, bool editable);
    void setCurrentFile(QWidget* page, const QString &fileName);
    bool saveFile(QWidget* page, const QString &fileName);
    void closeTabAt(int index);

    // 共用開檔（Open / Drop 都走這裡）
    void openFileInNewTab(const QString& fileName);

    // 關 tab 前詢問存檔
    bool maybeSaveTab(int index);

    // Ctrl+Tab 視覺化切換
    void showTabSwitcher(bool reverse);

    // 切換 Size 單位顯示
    void changeSizeUnit(int idx, qint64 size);
};

#endif // MAINWINDOW_H
