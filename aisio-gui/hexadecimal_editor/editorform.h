#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "hexdiffwidget.h"
#include "hexview.h"
#include "../text_editor/textview.h"
#include <QMainWindow>
#include <QWidget>
#include <QShowEvent>
#include <QLabel>
#include <QStatusBar>
#include <QTabWidget>
#include <QMetaObject>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QProgressBar>
#include <QFutureWatcher>

QT_BEGIN_NAMESPACE
namespace Ui { class EditorForm; }
QT_END_NAMESPACE

// ------------------------------------------------------------

class BusyOverlay : public QWidget {
    Q_OBJECT
public:
    explicit BusyOverlay(QWidget* parent)
        : QWidget(parent)
    {
        setAttribute(Qt::WA_NoSystemBackground);
        setAttribute(Qt::WA_TransparentForMouseEvents, false);
        setFocusPolicy(Qt::StrongFocus);
        setStyleSheet(R"(
            QProgressBar {
                background: transparent;
                border: none;
            }
            QProgressBar::chunk {
                background-color: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2828ff,
                    stop:1 #a6ffff);
            }
        )");
        // background-color: #2828ff;

        m_bar = new QProgressBar(this);
        m_bar->setRange(0, 0); // 不定進度
        m_bar->setTextVisible(false);
        m_bar->setFixedHeight(3);
    }

    void resizeEvent(QResizeEvent*) override {
        m_bar->setGeometry(0, 0, width(), 2); // tab 上方細條
    }

protected:
    // ⭐ 關鍵：吃掉滑鼠
    bool event(QEvent* e) override
    {
        switch (e->type()) {
        case QEvent::MouseButtonPress:
        case QEvent::MouseButtonRelease:
        case QEvent::MouseMove:
        case QEvent::Wheel:
        case QEvent::KeyPress:
        case QEvent::KeyRelease:
            return true;   // ⭐ 不往下傳
        default:
            return QWidget::event(e);
        }
    }

private:
    QProgressBar* m_bar;
};

// ------------------------------------------------------------

class EditorForm : public QMainWindow {
    Q_OBJECT

public:
    enum class ViewType {
        NoView,
        HexView,
        HexDiff,
        TextView,
        TextDiff,
    };
    Q_ENUM(ViewType);

    explicit EditorForm(QWidget *parent = nullptr);
    ~EditorForm();

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
    void nextPage();
    void prevPage();
    void closeTab();

    void undo();
    void redo();
    void copy();
    void paste();
    void interpret();

    void openSearchPanel();
    void findNext();
    void findPrevious();
    void gotoOffset();

    void diffOpen();
    void diffNext();
    void diffPrev();
    void diffClose();

    void onAsyncSaveFinished();

    void dataChanged();
    void shortcutKeyHelper();

private:
    Ui::EditorForm *ui;
    QTabWidget  *m_tabs         = nullptr;
    QStatusBar  *m_statusBar    = nullptr;
    QLabel *lbAddressName       = nullptr;
    QLineEdit *lineEditAddress  = nullptr;
    QLabel *lbSizeName          = nullptr;
    QLineEdit *lineEditSize     = nullptr;
    QComboBox *cbSizeUnit       = nullptr;
    BusyOverlay* m_busyOverlay  = nullptr;

    // background save (one at a time)
    bool m_saveRunning = false;
    QFutureWatcher<bool> m_saveWatcher;
    QWidget* m_savePage = nullptr;
    HexView*  m_saveView = nullptr;
    QString   m_saveFinalPath;
    QString   m_saveTmpPath;

    // tab 綁定的檔案資訊都存放在 page widget 的 dynamic property
    //  - "curFile"    : QString
    //  - "isUntitled" : bool
    //  - "isModified" : bool
    //  - "viewType"   : ViewType

    bool m_isClosingTab = false;
    const QString m_windowTitle = "AisIO Editor";

    void createStatusBar();
    void createAction();
    void createActionShortcutsText();
    void setupShortcuts();

    // tab helpers
    ViewType currentViewType() const;
    HexView* currentHexView() const;
    HexDiffWidget* currentHexDiffWidget() const;
    TextView* currentTextView() const;
    QWidget* currentPage() const;
    ViewType openWith();
    void attachStatusToView(HexView* view);

    int  addHexTab(QIODevice* dev, const QString& fileName, bool editable);
    int  addTextTab(QIODevice* dev, const QString& fileName, bool editable);
    void setCurrentFile(QWidget* page, const QString &fileName);
    bool saveFile(QWidget* page, const QString &fileName);
    bool saveFileAsync(QWidget* page, const QString &fileName);
    void closeTabAt(int index);

    // 進度條
    void beginBusy();
    void endBusy();

    // 共用開檔（Open / Drop 都走這裡）
    void openFileInNewTab(const QString& fileName, ViewType type = ViewType::NoView);

    // 關 tab 前詢問存檔
    bool maybeSaveTab(int index);

    // Ctrl+Tab 視覺化切換
    void showTabSwitcher(bool reverse);

    // 切換 Size 單位顯示
    void changeSizeUnit(int idx, qint64 size);

    // 更新狀態欄
    void updateStatusBar(const HexViewStatus& st);
};
Q_DECLARE_METATYPE(EditorForm::ViewType)

#endif // MAINWINDOW_H
