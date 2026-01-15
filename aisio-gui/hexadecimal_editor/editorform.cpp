#include "editorform.h"
#include "hexadecimal_editor/ui_editorform.h"
#include "hexview.h"
#include "../include/hexshortcutdialog.h"

#include <QFileDialog>
#include <QLineEdit>
#include <QMessageBox>
#include <QFileInfo>
#include <QShortcut>
#include <QMimeData>
#include <QUrl>
#include <QtConcurrent>

#include <QDialog>
#include <QListWidget>
#include <QVBoxLayout>
#include <QKeyEvent>
#include <QGuiApplication>
#include <QScreen>
#include <QComboBox>
#include <QSettings>
#include <QMetaType>
#include <QInputDialog>

// -------------------- Ctrl+Tab Popup Dialog --------------------
class TabSwitcherPopup : public QDialog {
public:
    TabSwitcherPopup(QTabWidget* tabs, QWidget* parent = nullptr)
        : QDialog(parent), m_tabs(tabs)
    {
        setWindowFlags(Qt::Popup | Qt::FramelessWindowHint);
        setAttribute(Qt::WA_DeleteOnClose, true);

        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(10, 10, 10, 10);

        m_list = new QListWidget(this);
        m_list->setSelectionMode(QAbstractItemView::SingleSelection);
        layout->addWidget(m_list);

        // 填入 tabs
        for (int i = 0; i < m_tabs->count(); ++i) {
            QString t = m_tabs->tabText(i);
            m_list->addItem(t);
        }

        // 美觀：跟你深色系接近（只影響 popup 自己）
        setStyleSheet(R"(
            QDialog { background:#1f1f1f; border:1px solid #3a3f4b; border-radius:10px; }
            QListWidget { background:#111317; color:#dfe3ea; border:1px solid #343a46; border-radius:8px; padding:6px; }
            QListWidget::item { padding:8px; }
            QListWidget::item:selected { background:#394359; }
        )");

        resize(520, 260);
    }

    void selectIndex(int idx) {
        if (idx < 0 || idx >= m_list->count()) return;
        m_list->setCurrentRow(idx);
    }

    int selectedIndex() const {
        return m_list->currentRow();
    }

protected:
    void keyPressEvent(QKeyEvent* e) override
    {
        // Ctrl+Tab / Ctrl+Shift+Tab 的重複切換
        if (e->key() == Qt::Key_Tab && (e->modifiers() & Qt::ControlModifier)) {
            bool reverse = (e->modifiers() & Qt::ShiftModifier);
            step(reverse);
            e->accept();
            return;
        }
        if (e->key() == Qt::Key_Backtab && (e->modifiers() & Qt::ControlModifier)) {
            step(true);
            e->accept();
            return;
        }

        if (e->key() == Qt::Key_Escape) {
            m_cancel = true;
            close();
            return;
        }

        QDialog::keyPressEvent(e);
    }

    void keyReleaseEvent(QKeyEvent* e) override
    {
        // 放開 Ctrl → 套用選擇並關閉
        if (e->key() == Qt::Key_Control) {
            close();
            return;
        }
        QDialog::keyReleaseEvent(e);
    }

    void closeEvent(QCloseEvent* ev) override
    {
        Q_UNUSED(ev);
        if (!m_tabs) return;
        if (!m_cancel) {
            int idx = selectedIndex();
            if (idx >= 0 && idx < m_tabs->count())
                m_tabs->setCurrentIndex(idx);
        }
    }

private:
    void step(bool reverse)
    {
        int n = m_list->count();
        if (n <= 0) return;
        int cur = m_list->currentRow();
        if (cur < 0) cur = 0;
        int next = reverse ? (cur - 1 + n) % n : (cur + 1) % n;
        m_list->setCurrentRow(next);
    }

    QTabWidget* m_tabs = nullptr;
    QListWidget* m_list = nullptr;
    bool m_cancel = false;
};

// ------------------------------------------------------------

EditorForm::EditorForm(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::EditorForm) {
    ui->setupUi(this);
    setWindowTitle(m_windowTitle);

    // 註冊 ViewType
    qRegisterMetaType<ViewType>("EditorForm::ViewType");

    // 允許拖曳檔案進來
    setAcceptDrops(true);

    // 用 QTabWidget 承載多個 HexView（每個 tab 一個檔案）
    m_tabs = new QTabWidget(ui->hexViewWidget);
    m_tabs->setDocumentMode(true);
    m_tabs->setTabsClosable(true);
    m_tabs->setMovable(true);

    // hexViewWidget 是 native widget，沒有 layout；沿用你原本 setGeometry 的做法
    m_tabs->setGeometry(ui->hexViewWidget->rect());
    m_tabs->show();

    // ⭐ 關 tab（含：若有 * 先詢問存檔）
    connect(m_tabs, &QTabWidget::tabCloseRequested, this, &EditorForm::closeTabAt);

    // 切 tab 時，statusbar 綁定到新的 HexView
    connect(m_tabs, &QTabWidget::currentChanged, this, [this](int) {
        HexView* view = currentHexView();
        attachStatusToView(view);

        if (!view) {
            setWindowTitle(m_windowTitle);
            return;
        }

        // 更新視窗標題
        QWidget* page = currentPage();
        if (!page) return;
        const QString fileName = page->property("curFile").toString();
        if (fileName.isEmpty())
            setWindowTitle(m_windowTitle);
        else
            setWindowTitle(QFileInfo(fileName).fileName() + " - " + m_windowTitle);
    });

    m_busyOverlay = new BusyOverlay(ui->hexViewWidget);
    m_busyOverlay->hide();

    qRegisterMetaType<HexViewStatus>("HexViewStatus");

    this->createStatusBar();
    this->createAction();
    this->createActionShortcutsText();
    this->setupShortcuts();

    // async save watcher
    connect(&m_saveWatcher, &QFutureWatcher<bool>::finished,
            this, &EditorForm::onAsyncSaveFinished);
}

EditorForm::~EditorForm() {
    delete ui;
}

void EditorForm::createStatusBar() {
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

    cbSizeUnit = new QComboBox(this);
    cbSizeUnit->addItem("B");
    cbSizeUnit->addItem("KB");
    cbSizeUnit->addItem("MB");
    cbSizeUnit->addItem("GB");
    cbSizeUnit->addItem("TB");
    cbSizeUnit->addItem("PB");
    cbSizeUnit->addItem("EB");
    cbSizeUnit->addItem("ZB");
    cbSizeUnit->addItem("YB");
    cbSizeUnit->setMinimumWidth(30);
    cbSizeUnit->setMaximumWidth(50);
    cbSizeUnit->setEditable(false);

    m_statusBar->addPermanentWidget(lbAddressName);
    m_statusBar->addPermanentWidget(lineEditAddress);
    m_statusBar->addPermanentWidget(lbSizeName);
    m_statusBar->addPermanentWidget(lineEditSize);
    m_statusBar->addPermanentWidget(cbSizeUnit);

    this->attachStatusToView(currentHexView());

    m_statusBar->showMessage(m_windowTitle + tr(" is Ready!"), 2000);
}

void EditorForm::createAction() {
    // File
    connect(ui->actionNew, SIGNAL(triggered()), this, SLOT(create()));
    connect(ui->actionOpen, SIGNAL(triggered()), this, SLOT(open()));
    connect(ui->actionSave, SIGNAL(triggered()), this, SLOT(save()));
    connect(ui->actionSaveAs, SIGNAL(triggered()), this, SLOT(saveAs()));
    connect(ui->actionNextPage, SIGNAL(triggered()), this, SLOT(nextPage()));
    connect(ui->actionPrevPage, SIGNAL(triggered()), this, SLOT(prevPage()));
    connect(ui->actionClose, SIGNAL(triggered()), this, SLOT(closeTab()));
    connect(ui->actionExit, SIGNAL(triggered()), this, SLOT(close()));

    // Edit
    connect(ui->actionUndo, SIGNAL(triggered()), this, SLOT(undo()));
    connect(ui->actionRedo, SIGNAL(triggered()), this, SLOT(redo()));
    connect(ui->actionCopy, SIGNAL(triggered()), this, SLOT(copy()));
    connect(ui->actionPaste, SIGNAL(triggered()), this, SLOT(paste()));
    connect(ui->actionOpenCloseInterpret, SIGNAL(triggered()), this, SLOT(interpret()));

    // Search
    connect(ui->actionSearch, SIGNAL(triggered()), this, SLOT(openSearchPanel()));
    connect(ui->actionFindNext, SIGNAL(triggered()), this, SLOT(findNext()));
    connect(ui->actionFindPrev, SIGNAL(triggered()), this, SLOT(findPrevious()));
    connect(ui->actionGotoOffset, SIGNAL(triggered()), this, SLOT(gotoOffset()));

    // Diff
    connect(ui->actionDiffOpen, SIGNAL(triggered()), this, SLOT(diffOpen()));
    connect(ui->actionDiffNext, SIGNAL(triggered()), this, SLOT(diffNext()));
    connect(ui->actionDiffPrev, SIGNAL(triggered()), this, SLOT(diffPrev()));
    connect(ui->actionDiffClose, SIGNAL(triggered()), this, SLOT(diffClose()));

    // About
    connect(ui->actionShortcutKey, SIGNAL(triggered()), this, SLOT(shortcutKeyHelper()));

    // Other
    connect(cbSizeUnit, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int idx) {
        HexView *view = this->currentHexView();
        HexDiffWidget *diff = this->currentHexDiffWidget();
        if (!view && !diff)
            return;
        if (view)
            this->changeSizeUnit(idx, view->getBaseBytesLength());
        else if (diff)
            this->changeSizeUnit(idx, diff->leftView()->getBaseBytesLength());
    });
}

void EditorForm::createActionShortcutsText() {
    // File
    ui->actionNew->setText(     ui->actionNew->text()                           + QString("\t%1").arg("Ctrl+N"));
    ui->actionOpen->setText(    ui->actionOpen->text()                          + QString("\t%1").arg("Ctrl+O"));
    ui->actionSave->setText(    ui->actionSave->text()                          + QString("\t%1").arg("Ctrl+S"));
    ui->actionSaveAs->setText(  ui->actionSaveAs->text()                        + QString("\t%1").arg("Ctrl+Shift+S"));
    ui->actionNextPage->setText(ui->actionNextPage->text()                      + QString("\t%1").arg("Ctrl+Tab"));
    ui->actionPrevPage->setText(ui->actionPrevPage->text()                      + QString("\t%1").arg("Ctrl+Shift+Tab"));
    ui->actionClose->setText(   ui->actionClose->text()                         + QString("\t%1").arg("Ctrl+W"));
    ui->actionExit->setText(    ui->actionExit->text()                          + QString("\t%1").arg("Ctrl+Q"));

    // Edit
    ui->actionUndo->setText(ui->actionUndo->text()                              + QString("\t%1").arg("Ctrl+Z"));
    ui->actionRedo->setText(ui->actionRedo->text()                              + QString("\t%1").arg("Ctrl+Y"));
    ui->actionCopy->setText(ui->actionCopy->text()                              + QString("\t%1").arg("Ctrl+C"));
    ui->actionPaste->setText(ui->actionPaste->text()                            + QString("\t%1").arg("Ctrl+V"));
    ui->actionOpenCloseInterpret->setText(ui->actionOpenCloseInterpret->text()  + QString("\t%1").arg("Ctrl+D"));

    // Search
    ui->actionSearch->setText(ui->actionSearch->text()                          + QString("\t%1").arg("Ctrl+F"));
    ui->actionFindNext->setText(ui->actionFindNext->text()                      + QString("\t%1").arg("F3"));
    ui->actionFindPrev->setText(ui->actionFindPrev->text()                      + QString("\t%1").arg("Shift+F3"));
    ui->actionGotoOffset->setText(ui->actionGotoOffset->text()                  + QString("\t%1").arg("Ctrl+G"));

    // Diff
    ui->actionDiffOpen->setText(ui->actionDiffOpen->text()                      + QString("\t%1").arg("Ctrl+K"));
    ui->actionDiffNext->setText(ui->actionDiffNext->text()                      + QString("\t%1").arg("F6"));
    ui->actionDiffPrev->setText(ui->actionDiffPrev->text()                      + QString("\t%1").arg("Shift+F6"));
    ui->actionDiffClose->setText(ui->actionDiffClose->text()                    + QString("\t%1").arg("Ctrl+Shift+K"));
}

void EditorForm::setupShortcuts() {
    // ⭐ Ctrl+Tab 視覺化切換（含反向 Ctrl+Shift+Tab）
    QShortcut* sw = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_Tab), this);
    connect(sw, &QShortcut::activated, this, [this]() { showTabSwitcher(false); });

    QShortcut* swr = new QShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_Tab), this);
    connect(swr, &QShortcut::activated, this, [this]() { showTabSwitcher(true); });

    QShortcut* closeTab = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_W), this);
    connect(closeTab, &QShortcut::activated, this, &EditorForm::closeTab);

    QShortcut* close = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_Q), this);
    connect(close, &QShortcut::activated, this, &EditorForm::close);

    QShortcut* newFile = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_N), this);
    connect(newFile, &QShortcut::activated, this, &EditorForm::create);
    // ui->actionNew->setShortcuts(QKeySequence::Open);

    QShortcut* openFile = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_O), this);
    connect(openFile, &QShortcut::activated, this, &EditorForm::open);

    QShortcut* saveFile = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_S), this);
    connect(saveFile, &QShortcut::activated, this, &EditorForm::save);

    QShortcut* saveAsFile = new QShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_S), this);
    connect(saveAsFile, &QShortcut::activated, this, &EditorForm::saveAs);

    QShortcut* openDiff = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_K), this);
    connect(openDiff, &QShortcut::activated, this, &EditorForm::diffOpen);

    QShortcut* closeDiff = new QShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_K), this);
    connect(closeDiff, &QShortcut::activated, this, &EditorForm::diffClose);
}

EditorForm::ViewType EditorForm::currentViewType() const
{
    QWidget* page = currentPage();
    if (!page || !m_tabs) return ViewType::NoView; // 預設，不重要

    return page->property("viewType").value<ViewType>();
}

HexView* EditorForm::currentHexView() const {
    // if (!m_tabs) return nullptr;
    // return qobject_cast<HexView*>(m_tabs->currentWidget());
    if (currentViewType() != ViewType::HexView)
        return nullptr;
    return qobject_cast<HexView*>(currentPage());
}

HexDiffWidget* EditorForm::currentHexDiffWidget() const {
    // if (!m_tabs) return nullptr;
    // return qobject_cast<HexDiffWidget*>(m_tabs->currentWidget());
    if (currentViewType() != ViewType::HexDiff)
        return nullptr;
    return qobject_cast<HexDiffWidget*>(currentPage());
}

TextView* EditorForm::currentTextView() const
{
    if (currentViewType() != ViewType::TextView)
        return nullptr;
    return qobject_cast<TextView*>(currentPage());
}

QWidget* EditorForm::currentPage() const {
    return m_tabs ? m_tabs->currentWidget() : nullptr;
}

EditorForm::ViewType EditorForm::openWith() {
    QMessageBox box(this);
    box.setStyleSheet("* { background:#222222; color:#f0f0f0; }");
    box.setWindowTitle(tr("Open with..."));
    box.setText(tr("Select the editor you want to use."));
    box.addButton(tr("Hex Editor"), QMessageBox::AcceptRole);
    box.addButton(tr("Text Editor"), QMessageBox::ActionRole);
    box.addButton(QMessageBox::Cancel);
    box.exec();
    auto role = box.buttonRole(box.clickedButton());
    if (box.clickedButton() == nullptr ||
        role == QMessageBox::NRoles)
        return ViewType::NoView;
    if (role == QMessageBox::AcceptRole)
        return ViewType::HexView;
    else if (role == QMessageBox::ActionRole)
        return ViewType::TextView;
    else
        return ViewType::NoView;
}

void EditorForm::attachStatusToView(HexView* view)
{
    if (!view) {
        lineEditAddress->clear();
        lineEditSize->clear();
        return;
    }

    connect(view, &HexView::statusChanged, this, &EditorForm::updateStatusBar, Qt::UniqueConnection);

    view->setFocus();
    setAddress(view->currentOffset());
    setSize(view->getBytesLength());
}

int EditorForm::addHexTab(QIODevice* dev, const QString& fileName, bool editable)
{
    auto *view = new HexView(m_tabs);
    view->loadDevice(dev);
    view->setEditable(editable);

    // tab 狀態存在 view widget 自己的 property
    view->setProperty("curFile", fileName);
    view->setProperty("isUntitled", fileName.isEmpty());
    view->setProperty("isModified", false);
    view->setProperty("viewType", QVariant::fromValue(ViewType::HexView));

    view->setFocus();

    connect(view, &HexView::statusChanged, this, [this, view](const HexViewStatus& st) {
        int idx = m_tabs->indexOf(view);
        if (idx < 0) return;

        view->setProperty("isModified", st.isModified);

        QString title = m_tabs->tabText(idx);
        bool hasStar = title.endsWith('*');

        if (st.isModified && !hasStar) title += "*";
        if (!st.isModified && hasStar) title.chop(1);

        m_tabs->setTabText(idx, title);

        // 若這個 view 是目前 tab，同步視窗標題（讓 * 也能顯示在 title 的字串裡）
        if (m_tabs->currentWidget() == view) {
            QString base = m_windowTitle;
            QString fn = view->property("curFile").toString();
            QString shown = fn.isEmpty() ? base : (QFileInfo(fn).fileName() + " - " + base);
            if (st.isModified) shown += "*";
            setWindowTitle(shown);
        }
    });
    connect(view,  &HexView::progressStarted,  this, &EditorForm::beginBusy, Qt::UniqueConnection);
    connect(view,  &HexView::progressFinished, this, &EditorForm::endBusy,   Qt::UniqueConnection);

    QString title = fileName.isEmpty() ? tr("Untitled") : QFileInfo(fileName).fileName();
    int idx = m_tabs->addTab(view, title);
    m_tabs->setCurrentIndex(idx);

    // 讓 statusbar 顯示即時更新
    attachStatusToView(view);
    setCurrentFile(view, fileName);
    return idx;
}

int  EditorForm::addTextTab(QIODevice* dev, const QString& fileName, bool editable) {
    auto *view = new TextView(m_tabs);
    view->loadDevice(dev);
    // view->setEditable(editable);

    // tab 狀態存在 view widget 自己的 property
    view->setProperty("curFile", fileName);
    view->setProperty("isUntitled", fileName.isEmpty());
    view->setProperty("isModified", false);
    view->setProperty("viewType", QVariant::fromValue(ViewType::TextView));

    view->setFocus();

    connect(view, &TextView::progressStarted,  this, &EditorForm::beginBusy, Qt::UniqueConnection);
    connect(view, &TextView::progressFinished, this, &EditorForm::endBusy,   Qt::UniqueConnection);

    QString title = fileName.isEmpty() ? tr("Untitled") : QFileInfo(fileName).fileName();
    int idx = m_tabs->addTab(view, title);
    m_tabs->setCurrentIndex(idx);

    // 讓 statusbar 顯示即時更新
    // attachStatusToView(view);
    setCurrentFile(view, fileName);
    return idx;
}

void EditorForm::setCurrentFile(QWidget* page, const QString &fileName) {
    if (!page) return;
    const QString canonical = fileName.isEmpty() ? QString() : QFileInfo(fileName).canonicalFilePath();

    page->setProperty("curFile", canonical);
    page->setProperty("isUntitled", canonical.isEmpty());
    page->setProperty("isModified", false);

    // 更新 tab 標題
    int idx = m_tabs ? m_tabs->indexOf(page) : -1;
    if (idx >= 0) {
        QString title = canonical.isEmpty() ? tr("Untitled") : QFileInfo(canonical).fileName();
        m_tabs->setTabText(idx, title);
    }

    setWindowModified(false);
    if (canonical.isEmpty()) {
        setWindowFilePath(m_windowTitle);
        setWindowTitle(m_windowTitle);
    }
    else {
        setWindowFilePath(canonical + " - " + m_windowTitle);
        setWindowTitle(QFileInfo(canonical).fileName() + " - " + m_windowTitle);
    }
}

bool EditorForm::saveFile(QWidget* page, const QString &fileName) {
    HexView* view = qobject_cast<HexView*>(page);
    HexDiffWidget *diff = qobject_cast<HexDiffWidget *>(page);
    if (!view && !diff) return false;

    QString tmpFileName = fileName + ".~tmp";

    QApplication::setOverrideCursor(Qt::WaitCursor);
    QFile file(tmpFileName);
    bool ok = false;
    if (view)
        ok = view->saveToFile(tmpFileName);
    else if (diff && diff->leftView()->hasFocus())
        ok = diff->leftView()->saveToFile(tmpFileName);
    else if (diff && diff->rightView()->hasFocus())
        ok = diff->rightView()->saveToFile(tmpFileName);
    else
        return false;

    if (QFile::exists(fileName))
        ok = QFile::remove(fileName);
    if (ok)
    {
        file.setFileName(tmpFileName);
        ok = file.copy(fileName);
        if (ok) {
            ok = QFile::remove(tmpFileName);
            page->setProperty("isModified", false);
            setWindowModified(false);
            if (view){
                view->setIsModified(false);
                view->emitStatus(QString("File '%1' saved.").arg(fileName));
            }
            else if (diff && diff->leftView()->hasFocus()){
                diff->leftView()->setIsModified(false);
                diff->leftView()->emitStatus(QString("File '%1' saved.").arg(fileName));
            }
            else if (diff && diff->rightView()->hasFocus()){
                diff->rightView()->setIsModified(false);
                diff->rightView()->emitStatus(QString("File '%1' saved.").arg(fileName));
            }
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

    setCurrentFile(page, fileName);
    return true;
}

bool EditorForm::saveFileAsync(QWidget* page, const QString &fileName)
{
    if (m_saveRunning)
        return false;

    HexView* view = qobject_cast<HexView*>(page);
    HexDiffWidget *diff = qobject_cast<HexDiffWidget *>(page);
    if (!view && !diff) return false;

    // decide which view to save
    if (!view) {
        if (diff && diff->leftView()->hasFocus()) view = diff->leftView();
        else if (diff && diff->rightView()->hasFocus()) view = diff->rightView();
        else view = diff->leftView();
    }
    if (!view) return false;

    m_saveRunning = true;
    m_savePage = page;
    m_saveView = view;
    m_saveFinalPath = fileName;
    m_saveTmpPath = fileName + ".~tmp";

    beginBusy();

    // capture pointers for worker (OverlayMap / ChunksLite are now internally locked)
    OverlayMap* overlay = &view->overlay();
    ChunksLite* chunks  = view->chunks();

    auto future = QtConcurrent::run([overlay, chunks, tmp = m_saveTmpPath]() -> bool {
        if (!chunks) return false;
        QFile file(tmp);
        if (!file.open(QIODevice::WriteOnly))
            return false;

        const qint64 totalSize = overlay->size();
        const qint64 BUF = 0x10000;
        qint64 written = 0;
        while (written < totalSize) {
            qint64 len = qMin<qint64>(BUF, totalSize - written);
            QByteArray data = overlay->read(written, len, chunks);
            if (data.size() != len) {
                file.close();
                return false;
            }
            if (file.write(data) != data.size()) {
                file.close();
                return false;
            }
            written += len;
        }
        file.flush();
        file.close();
        return true;
    });

    m_saveWatcher.setFuture(future);
    return true;
}

void EditorForm::onAsyncSaveFinished()
{
    const bool okWrite = m_saveWatcher.result();
    endBusy();

    const QString finalName = m_saveFinalPath;
    const QString tmpName   = m_saveTmpPath;

    m_saveRunning = false;

    if (!okWrite) {
        if (!tmpName.isEmpty()) QFile::remove(tmpName);
        QMessageBox box(this);
        box.setIcon(QMessageBox::Critical);
        box.setWindowTitle(tr("Save failed"));
        box.setText(tr("Cannot write file %1.").arg(finalName));
        box.setStyleSheet("* { background:#222222; color:#f0f0f0; }");
        box.exec();
        return;
    }

    bool ok = true;
    if (QFile::exists(finalName))
        ok = QFile::remove(finalName);
    if (ok) {
        // try atomic rename
        ok = QFile::rename(tmpName, finalName);
        if (!ok) {
            QFile f(tmpName);
            ok = f.copy(finalName);
            if (ok) QFile::remove(tmpName);
        }
    }

    if (!ok) {
        QMessageBox box(this);
        box.setIcon(QMessageBox::Critical);
        box.setWindowTitle(tr("Save failed"));
        box.setText(tr("Cannot write file %1.").arg(finalName));
        box.setStyleSheet("* { background:#222222; color:#f0f0f0; }");
        box.exec();
        return;
    }

    if (m_savePage)
        m_savePage->setProperty("isModified", false);
    if (m_saveView) {
        m_saveView->setIsModified(false);
        m_saveView->emitStatus(QString("File '%1' saved.").arg(finalName));
    }

    if (m_savePage)
        setCurrentFile(m_savePage, finalName);
}

void EditorForm::closeTabAt(int index)
{
    // ⭐ 防止 re-entrancy
    if (m_isClosingTab)
        return;

    if (index < 0 || index >= m_tabs->count())
        return;

    m_isClosingTab = true;

    if (!maybeSaveTab(index)) {
        m_isClosingTab = false;
        return;
    }

    QWidget* page = m_tabs->widget(index);
    if (page) {
        m_tabs->removeTab(index);
        page->deleteLater();
    }

    m_isClosingTab = false;
}

void EditorForm::beginBusy() {
    if (!m_busyOverlay) return;
    m_busyOverlay->setGeometry(ui->hexViewWidget->rect());
    m_busyOverlay->show();
    m_busyOverlay->raise();
    m_busyOverlay->update();
}

void EditorForm::endBusy() {
    if (!m_busyOverlay) return;
    m_busyOverlay->update();
    m_busyOverlay->hide();
}

void EditorForm::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);

    // 視窗大小改變 → 讓 TabWidget 填滿 hexViewWidget
    if (m_tabs)
        m_tabs->setGeometry(ui->hexViewWidget->rect());

    if (m_busyOverlay && m_busyOverlay->isVisible())
        m_busyOverlay->setGeometry(ui->hexViewWidget->rect());
}

void EditorForm::showEvent(QShowEvent *event)
{
    QWidget::showEvent(event);

    if (m_tabs)
        m_tabs->setGeometry(ui->hexViewWidget->rect());
}

// -------------------- Drag & Drop --------------------

void EditorForm::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData() && event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
        return;
    }
    QMainWindow::dragEnterEvent(event);
}

void EditorForm::dropEvent(QDropEvent *event)
{
    if (!event->mimeData() || !event->mimeData()->hasUrls()) {
        QMainWindow::dropEvent(event);
        return;
    }

    const QList<QUrl> urls = event->mimeData()->urls();
    for (const QUrl& u : urls) {
        if (!u.isLocalFile()) continue;
        const QString path = u.toLocalFile();
        if (!path.isEmpty())
            openFileInNewTab(path);
    }
    event->acceptProposedAction();
}

// ============SLOTS============

void EditorForm::setAddress(qint64 address) {
    HexView* view = currentHexView();
    HexDiffWidget *diff = currentHexDiffWidget();
    if (!view && !diff) return;
    if (view)
        lineEditAddress->setText(QString("%1").arg(address, view->getaddressChars(), 16, QLatin1Char('0')).toUpper());
    else if (diff) {
        qint64 leftLen = diff->leftView()->getBytesLength();
        qint64 rightLen = diff->rightView()->getBytesLength();
        int chars = rightLen > leftLen ? diff->rightView()->getaddressChars() : diff->leftView()->getaddressChars();
        lineEditAddress->setText(QString("%1").arg(address, chars, 16, QLatin1Char('0')).toUpper());
    }
}

void EditorForm::setSize(qint64 size) {
    this->changeSizeUnit(cbSizeUnit->currentIndex(), size);
}

void EditorForm::create() {
    EditorForm::ViewType type = openWith();
    switch (type) {
    case ViewType::HexView: {
        // 初始的 device 也放進第一個 tab
        QString initialName;
        QIODevice *dev = nullptr;
        if (auto *qf = qobject_cast<QFile *>(dev)) {
            initialName = qf->fileName();
        }
        addHexTab(dev, initialName, true);
        return;
    }
    case ViewType::TextView: {
        // 初始化 TextView 介面
        QString initialName;
        QIODevice *dev = nullptr;
        if (auto *qf = qobject_cast<QFile *>(dev)) {
            initialName = qf->fileName();
        }
        addTextTab(dev, initialName, true);
        return;
    }
    case ViewType::NoView:
        return;
    default:
        m_statusBar->showMessage(tr("Not developed function!"), 3000);
        return;
    }
}

void EditorForm::open() {
    EditorForm::ViewType type = openWith();
    switch (type) {
    case ViewType::HexView: {
        QSettings settings;
        QString lastDir = settings.value("LastDir", QDir::homePath()).toString();

        QString fileName = QFileDialog::getOpenFileName(this, tr("Open"), lastDir);
        if (!fileName.isEmpty()) {
            settings.setValue("LastDir", QFileInfo(fileName).absolutePath());
            openFileInNewTab(fileName, ViewType::HexView);
        }
        return;
    }
    case ViewType::TextView: {
        QSettings settings;
        QString lastDir = settings.value("LastDir", QDir::homePath()).toString();

        QString fileName = QFileDialog::getOpenFileName(this, tr("Open"), lastDir);
        if (!fileName.isEmpty()) {
            settings.setValue("LastDir", QFileInfo(fileName).absolutePath());
            openFileInNewTab(fileName, ViewType::TextView);
        }
        return;
    }
    case ViewType::NoView:
        return;
    default:
        m_statusBar->showMessage(tr("Not developed function!"), 3000);
        return;
    }
}

void EditorForm::openFileInNewTab(const QString& fileName, ViewType type) {
    if (fileName.isEmpty())
        return;

    QFile *file = new QFile(fileName, this);
    int idx = -1;
    switch (type) {
    case ViewType::HexView:
        idx = addHexTab(file, fileName, true);
        break;
    case ViewType::TextView:
        idx = addTextTab(file, fileName, true);
        break;
    case ViewType::NoView:
        return;
    default:
        m_statusBar->showMessage(tr("Non type with open the file."), 3000);
        return;
    }

    // int idx = addHexTab(file, fileName, true);
    QWidget* page = m_tabs->widget(idx);
    file->setParent(page);

    statusBar()->showMessage(tr("File loaded..."), 2000);
}

bool EditorForm::save() {
    QWidget* page = currentPage();
    if (!page) return false;

    const bool isUntitled = page->property("isUntitled").toBool();
    const QString curFile = page->property("curFile").toString();

    // During close-tab flow we must save synchronously (so the close decision is correct).
    const bool forceSync = m_isClosingTab;

    if (isUntitled)
        return saveAs();

    if (forceSync)
        return saveFile(page, curFile);

    // Normal Ctrl+S / menu Save: run in background with progress bar.
    return saveFileAsync(page, curFile);
}

bool EditorForm::saveAs() {
    QWidget* page = currentPage();
    if (!page) return false;

    const QString curFile = page->property("curFile").toString();
    QString fileName = QFileDialog::getSaveFileName(this, tr("Save As"), curFile);
    if (fileName.isEmpty())
        return false;

    if (m_isClosingTab)
        return saveFile(page, fileName);
    return saveFileAsync(page, fileName);
}

void EditorForm::nextPage() {
    int idx = m_tabs->currentIndex();
    if (idx < m_tabs->count() - 1)
        m_tabs->setCurrentIndex(idx + 1);
    else
        m_tabs->setCurrentIndex(0);
}

void EditorForm::prevPage() {
    int idx = m_tabs->currentIndex();
    if (idx > 0)
        m_tabs->setCurrentIndex(idx - 1);
    else
        m_tabs->setCurrentIndex(m_tabs->count() - 1);
}

void EditorForm::closeTab() {
    int idx = m_tabs->currentIndex();
    if (idx >= 0)
        closeTabAt(m_tabs->currentIndex());
}

void EditorForm::openSearchPanel() {
    HexView *view = this->currentHexView();
    HexDiffWidget *diff = this->currentHexDiffWidget();
    TextView *tv = this->currentTextView();
    if (!view && !diff && !tv)
        return;
    if (view)
        view->openSearchPanel();
    else if (diff && diff->leftView()->hasFocus())
        diff->leftView()->openSearchPanel();
    else if (diff && diff->rightView()->hasFocus())
        diff->rightView()->openSearchPanel();
    else if (tv) {
        tv->openSearchPanel();
        return;
    }
}

void EditorForm::findNext() {
    HexView *view = this->currentHexView();
    HexDiffWidget *diff = this->currentHexDiffWidget();
    TextView *tv = this->currentTextView();
    if (!view && !diff && !tv)
        return;
    if (view)
        view->findNext();
    else if (diff && diff->leftView()->hasFocus())
        diff->leftView()->findNext();
    else if (diff && diff->rightView()->hasFocus())
        diff->rightView()->findNext();
    else if (tv) {
        tv->findNext();
        return;
    }
}

void EditorForm::findPrevious() {
    HexView *view = this->currentHexView();
    HexDiffWidget *diff = this->currentHexDiffWidget();
    TextView *tv = this->currentTextView();
    if (!view && !diff && !tv)
        return;
    if (view)
        view->findPrev();
    else if (diff && diff->leftView()->hasFocus())
        diff->leftView()->findPrev();
    else if (diff && diff->rightView()->hasFocus())
        diff->rightView()->findPrev();
    else if (tv) {
        tv->findPrev();
        return;
    }
}

void EditorForm::gotoOffset() {
    HexView *view = this->currentHexView();
    HexDiffWidget *diff = this->currentHexDiffWidget();
    TextView *tv = this->currentTextView();
    if (!view && !diff && !tv)
        return;
    if (view)
        view->gotoOffset();
    else if (diff && diff->leftView()->hasFocus())
        diff->leftView()->gotoOffset();
    else if (diff && diff->rightView()->hasFocus())
        diff->rightView()->gotoOffset();
    else if (tv) {
        tv->openGotoPanel();
        return;
    }
}

void EditorForm::undo() {
    HexView *view = this->currentHexView();
    HexDiffWidget *diff = this->currentHexDiffWidget();
    if (!view && !diff)
        return;
    if (view)
        view->undo();
    else if (diff && diff->leftView()->hasFocus())
        diff->leftView()->undo();
    else if (diff && diff->rightView()->hasFocus())
        diff->rightView()->undo();
}

void EditorForm::redo() {
    HexView *view = this->currentHexView();
    HexDiffWidget *diff = this->currentHexDiffWidget();
    if (!view && !diff)
        return;
    if (view)
        view->redo();
    else if (diff && diff->leftView()->hasFocus())
        diff->leftView()->redo();
    else if (diff && diff->rightView()->hasFocus())
        diff->rightView()->redo();
}

void EditorForm::copy() {
    HexView *view = this->currentHexView();
    HexDiffWidget *diff = this->currentHexDiffWidget();
    if (!view && !diff)
        return;
    if (view)
        view->copySelectionToClipboard();
    else if (diff && diff->leftView()->hasFocus())
        diff->leftView()->copySelectionToClipboard();
    else if (diff && diff->rightView()->hasFocus())
        diff->rightView()->copySelectionToClipboard();
}

void EditorForm::paste() {
    HexView *view = this->currentHexView();
    HexDiffWidget *diff = this->currentHexDiffWidget();
    if (!view && !diff)
        return;
    if (view)
        view->pasteFromClipboard();
    else if (diff && diff->leftView()->hasFocus())
        diff->leftView()->pasteFromClipboard();
    else if (diff && diff->rightView()->hasFocus())
        diff->rightView()->pasteFromClipboard();
}

void EditorForm::interpret() {
    HexView *view = this->currentHexView();
    HexDiffWidget *diff = this->currentHexDiffWidget();
    if (!view && !diff)
        return;
    if (view)
        view->openInterpretPanel();
    else if (diff && diff->leftView()->hasFocus())
        diff->leftView()->openInterpretPanel();
    else if (diff && diff->rightView()->hasFocus())
        diff->rightView()->openInterpretPanel();
}

void EditorForm::dataChanged() {
    QWidget* page = currentPage();
    if (!page) return;

    page->setProperty("isModified", true);
    setWindowModified(true);
}

void EditorForm::shortcutKeyHelper() {
    HexShortcutDialog dlg(this);
    dlg.exec();
}

void EditorForm::diffOpen()
{
    int idx = m_tabs->currentIndex();
    if (idx < 0) {
        m_statusBar->showMessage(tr("Please create or open a file first."), 3000);
        return;
    }

    QWidget *w = m_tabs->widget(idx);

    // 只允許在「單一 HexView」上啟動 diff
    HexView *left = qobject_cast<HexView*>(w);
    if (!left) {
        m_statusBar->showMessage(tr("Please close the current diff first."), 3000);
        return;
    }

    // 讓使用者選第二個檔案
    QString path = QFileDialog::getOpenFileName(
        this,
        tr("Select file to compare"),
        QString(),
        tr("All Files (*)")
        );
    if (path.isEmpty())
        return;

    QFile *f = new QFile(path, this);
    if (!f->open(QIODevice::ReadOnly))
        return;

    // 建立右邊 HexView
    HexDiffWidget *diff = new HexDiffWidget;
    diff->leftView()->loadDevice(left->chunks()->getDevice());
    diff->rightView()->loadDevice(f);

    diff->leftView()->setDiffNavSources(
        &diff->leftView()->overlay(), &diff->rightView()->overlay());

    diff->rightView()->setDiffNavSources(
        &diff->leftView()->overlay(), &diff->rightView()->overlay());

    // ✅ Diff 模式下：真正跑 diffFindNext/Prev 的是 diff->leftView()，必須把它的 busy 訊號接到 EditorForm
    connect(diff->leftView(),  &HexView::progressStarted,  this, &EditorForm::beginBusy, Qt::UniqueConnection);
    connect(diff->leftView(),  &HexView::progressFinished, this, &EditorForm::endBusy,   Qt::UniqueConnection);

    // （可選）如果你之後右邊也會跑 diff，就也接上
    connect(diff->rightView(), &HexView::progressStarted,  this, &EditorForm::beginBusy, Qt::UniqueConnection);
    connect(diff->rightView(), &HexView::progressFinished, this, &EditorForm::endBusy,   Qt::UniqueConnection);

    attachStatusToView(diff->leftView());
    attachStatusToView(diff->rightView());

    // 用 diff widget 取代原本的 tab
    // ⭐ 繼承原 tab 的狀態
    diff->setProperty("curFile", w->property("curFile"));
    diff->setProperty("isUntitled", w->property("isUntitled"));
    diff->setProperty("isModified", w->property("isModified"));
    diff->setProperty("viewType", QVariant::fromValue(ViewType::HexDiff));
    QWidget* page = currentPage();
    const QString fileName = QFileInfo(page->property("curFile").toString()).fileName();
    const QString diffFileName = QFileInfo(path).fileName();
    m_tabs->removeTab(idx);
    m_tabs->insertTab(idx, diff, QString("%1 / %2").arg(fileName, diffFileName));
    m_tabs->setCurrentIndex(idx);

    diff->leftView()->emitStatus();
}

void EditorForm::diffNext() {
    HexDiffWidget *diff = this->currentHexDiffWidget();
    if (!diff) {
        m_statusBar->showMessage(tr("Diff are not currently enabled."), 3000);
        return;
    }
    diff->leftView()->diffFindNext();
}

void EditorForm::diffPrev() {
    HexDiffWidget *diff = this->currentHexDiffWidget();
    if (!diff) {
        m_statusBar->showMessage(tr("Diff are not currently enabled."), 3000);
        return;
    }
    diff->leftView()->diffFindPrev();
}

void EditorForm::diffClose() {
    QWidget *page = currentPage();
    if (!page || page->property("viewType").value<ViewType>() != ViewType::HexDiff) {
        m_statusBar->showMessage(tr("Diff are not currently enabled."), 3000);
        return;
    }
    HexDiffWidget *diff = currentHexDiffWidget();
    if (!diff) {
        m_statusBar->showMessage(tr("Diff are not currently enabled."), 3000);
        return;
    }

    int idx = m_tabs->currentIndex();
    if (idx < 0)
        return;

    // 把左邊 view 拿回來（保留它的資料/游標狀態）
    HexView *left = diff->leftView();
    left->setParent(m_tabs);

    // 繼承原 tab 狀態
    left->setProperty("curFile",    diff->property("curFile"));
    left->setProperty("isUntitled", diff->property("isUntitled"));
    left->setProperty("isModified", diff->property("isModified"));
    left->setProperty("viewType",   diff->property("viewType"));

    // 用左邊 view 取代 diff tab
    QString title;
    const QString curFile = left->property("curFile").toString();
    if (curFile.isEmpty()) title = tr("Untitled");
    else title = QFileInfo(curFile).fileName();

    m_tabs->removeTab(idx);
    m_tabs->insertTab(idx, left, title);
    m_tabs->setCurrentIndex(idx);

    // 離開 diff 時把 diff 狀態 reset（你的 diffClose 只做 lastDiff 清掉，OK）
    left->diffClose();

    // 刪掉 diff widget（只刪一次！）
    diff->deleteLater();

    // 重新 attach 狀態列（避免還接在 diff 裡的 view）
    attachStatusToView(left);

    left->emitStatus();
}

// -------------------- Close Tab Ask Save --------------------

bool EditorForm::maybeSaveTab(int index)
{
    QWidget* page = m_tabs->widget(index);
    if (!page) return true;

    const bool modified = page->property("isModified").toBool()
                          || (m_tabs->tabText(index).endsWith('*'));

    if (!modified)
        return true;

    const QString fileName = page->property("curFile").toString();
    const QString shown = fileName.isEmpty()
                              ? tr("Untitled")
                              : QFileInfo(fileName).fileName();

    QMessageBox box(this);
    box.setStyleSheet("* { background:#222222; color:#f0f0f0; }");
    box.setIcon(QMessageBox::Question);
    box.setWindowTitle(tr("Unsaved changes"));
    box.setText(tr("Save changes to \"%1\"?").arg(shown));
    box.setInformativeText(tr("Your changes will be lost if you don't save them."));
    QPushButton* btnSave    = box.addButton(tr("Save"), QMessageBox::AcceptRole);
    QPushButton* btnDiscard = box.addButton(tr("Don't Save"), QMessageBox::DestructiveRole);
    QPushButton* btnCancel  = box.addButton(tr("Cancel"), QMessageBox::RejectRole);
    Q_UNUSED(btnCancel);

    box.exec();
    auto role = box.buttonRole(box.clickedButton());

    if (role == QMessageBox::DestructiveRole)
        return true;

    if (role == QMessageBox::AcceptRole) {
        // save()/saveAs() 是針對 current tab，所以先切過去再存
        int old = m_tabs->currentIndex();
        m_tabs->setCurrentIndex(index);

        bool ok = save(); // 若使用者取消 SaveAs，會回傳 false
        if (!ok) {
            m_tabs->setCurrentIndex(old);
            return false;
        }
        return true;
    }

    return false; // Cancel
}

// -------------------- Ctrl+Tab Visual Switch --------------------

void EditorForm::showTabSwitcher(bool reverse)
{
    if (!m_tabs || m_tabs->count() <= 1)
        return;

    auto* pop = new TabSwitcherPopup(m_tabs, this);

    // 放在視窗中央
    QRect g = frameGeometry();
    QPoint center = g.center();
    QSize s = pop->size();
    pop->move(center.x() - s.width()/2, center.y() - s.height()/2);

    int cur = m_tabs->currentIndex();
    int n = m_tabs->count();
    int next = reverse ? (cur - 1 + n) % n : (cur + 1) % n;
    pop->selectIndex(next);

    pop->show();
    pop->raise();
    pop->activateWindow();
    pop->setFocus();
}

void EditorForm::changeSizeUnit(int idx, qint64 size) {
    if (size == 0)
        return;
    QString result = "";
    double byteunit = 0;
    switch (idx) {
    case 0:
        result = QString::number(size);
        break;
    case 1:
        byteunit = (double)size / 1024;
        break;
    case 2:
        byteunit = (double)size / 1024 / 1024;
        break;
    case 3:
        byteunit = (double)size / 1024 / 1024 / 1024;
        break;
    case 4:
        byteunit = (double)size / 1024 / 1024 / 1024 / 1024;
        break;
    case 5:
        byteunit = (double)size / 1024 / 1024 / 1024 / 1024 / 1024;
        break;
    case 6:
        byteunit = (double)size / 1024 / 1024 / 1024 / 1024 / 1024 / 1024;
        break;
    case 7:
        byteunit = (double)size / 1024 / 1024 / 1024 / 1024 / 1024 / 1024 / 1024;
        break;
    case 8:
        byteunit = (double)size / 1024 / 1024 / 1024 / 1024 / 1024 / 1024 / 1024 / 1024;
        break;
    default:break;
    }

    result = idx == 0 ? QString::number(size) : QString::number(byteunit, 'f', 3);
    lineEditSize->setText(result);
}

void EditorForm::updateStatusBar(const HexViewStatus& st)
{
    this->setAddress(st.cursorOffset);

    this->changeSizeUnit(cbSizeUnit->currentIndex(), st.fileSize);

    if (!st.message.isEmpty())
        this->m_statusBar->showMessage(st.message, 3000);
}
