#include "hexform.h"
#include "hexview.h"
#include "../include/hexshortcutdialog.h"
#include "ui_hexform.h"

#include <QFileDialog>
#include <QLineEdit>
#include <QMessageBox>
#include <QFileInfo>
#include <QShortcut>
#include <QMimeData>
#include <QUrl>

#include <QDialog>
#include <QListWidget>
#include <QVBoxLayout>
#include <QKeyEvent>
#include <QGuiApplication>
#include <QScreen>
#include <QComboBox>
#include <QSettings>

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

HexForm::HexForm(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::HexForm) {
    ui->setupUi(this);
    setWindowTitle(tr("Hexadecimal Editor"));

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
    connect(m_tabs, &QTabWidget::tabCloseRequested, this, &HexForm::closeTabAt);

    // 切 tab 時，statusbar 綁定到新的 HexView
    connect(m_tabs, &QTabWidget::currentChanged, this, [this](int) {
        HexView* view = currentHexView();
        attachStatusToView(view);

        if (!view) {
            setWindowTitle(tr("Hexadecimal Editor"));
            return;
        }

        // 更新視窗標題
        QWidget* page = currentPage();
        if (!page) return;
        const QString fileName = page->property("curFile").toString();
        if (fileName.isEmpty())
            setWindowTitle("Hexadecimal Editor");
        else
            setWindowTitle(QFileInfo(fileName).fileName() + " - Hexadecimal Editor");
    });

    this->createStatusBar();
    this->createAction();
    this->setupShortcuts();
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

    m_statusBar->showMessage(tr("Ready"), 2000);
}

void HexForm::createAction() {
    connect(ui->actionNew, SIGNAL(triggered()), this, SLOT(create()));
    connect(ui->actionOpen, SIGNAL(triggered()), this, SLOT(open()));
    connect(ui->actionSave, SIGNAL(triggered()), this, SLOT(save()));
    connect(ui->actionSave_As, SIGNAL(triggered()), this, SLOT(saveAs()));
    connect(ui->actionShortcutKey, SIGNAL(triggered()), this, SLOT(shortcutKeyHelper()));
    connect(cbSizeUnit, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int idx) {
        HexView *view = this->currentHexView();
        if (view == nullptr)
            return;
        this->changeSizeUnit(idx, view->getBaseBytesLength());
    });
}

void HexForm::setupShortcuts() {
    // ⭐ Ctrl+Tab 視覺化切換（含反向 Ctrl+Shift+Tab）
    QShortcut* sw = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_Tab), this);
    connect(sw, &QShortcut::activated, this, [this]() { showTabSwitcher(false); });

    QShortcut* swr = new QShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_Tab), this);
    connect(swr, &QShortcut::activated, this, [this]() { showTabSwitcher(true); });

    QShortcut* closeTab = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_W), this);
    connect(closeTab, &QShortcut::activated, this, [this]() {
        int idx = m_tabs->currentIndex();
        if (idx >= 0)
            closeTabAt(m_tabs->currentIndex());
    });

    QShortcut* newFile = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_N), this);
    connect(newFile, &QShortcut::activated, this, &HexForm::create);

    QShortcut* openFile = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_O), this);
    connect(openFile, &QShortcut::activated, this, &HexForm::open);

    QShortcut* saveFile = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_S), this);
    connect(saveFile, &QShortcut::activated, this, &HexForm::save);

    QShortcut* saveAsFile = new QShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_S), this);
    connect(saveAsFile, &QShortcut::activated, this, &HexForm::saveAs);
}

HexView* HexForm::currentHexView() const {
    if (!m_tabs) return nullptr;
    return qobject_cast<HexView*>(m_tabs->currentWidget());
}

QWidget* HexForm::currentPage() const {
    return m_tabs ? m_tabs->currentWidget() : nullptr;
}

void HexForm::attachStatusToView(HexView* view)
{
    // 換綁定（避免多重觸發）
    if (m_connCursor) QObject::disconnect(m_connCursor);
    if (m_connSize)   QObject::disconnect(m_connSize);

    if (!view) {
        lineEditAddress->clear();
        lineEditSize->clear();
        return;
    }

    m_connCursor = connect(view, &HexView::cursorChanged, this, &HexForm::setAddress);
    m_connSize   = connect(view, &HexView::dataSizeChanged, this, &HexForm::setSize);

    view->setFocus();
    setAddress(view->currentOffset());
    setSize(view->getBytesLength());
}

int HexForm::addHexTab(QIODevice* dev, const QString& fileName, bool editable)
{
    auto *view = new HexView(m_tabs);
    view->loadDevice(dev);
    view->setEditable(editable);

    // tab 狀態存在 view widget 自己的 property
    view->setProperty("curFile", fileName);
    view->setProperty("isUntitled", fileName.isEmpty());
    view->setProperty("isModified", false);

    view->setFocus();

    connect(view, &HexView::modifiedChanged, this, [this, view](bool modified) {
        int idx = m_tabs->indexOf(view);
        if (idx < 0) return;

        view->setProperty("isModified", modified);

        QString title = m_tabs->tabText(idx);
        bool hasStar = title.endsWith('*');

        if (modified && !hasStar) title += "*";
        if (!modified && hasStar) title.chop(1);

        m_tabs->setTabText(idx, title);

        // 若這個 view 是目前 tab，同步視窗標題（讓 * 也能顯示在 title 的字串裡）
        if (m_tabs->currentWidget() == view) {
            QString base = "Hexadecimal Editor";
            QString fn = view->property("curFile").toString();
            QString shown = fn.isEmpty() ? base : (QFileInfo(fn).fileName() + " - " + base);
            if (modified) shown += "*";
            setWindowTitle(shown);
        }
    });

    QString title = fileName.isEmpty() ? tr("Untitled") : QFileInfo(fileName).fileName();
    int idx = m_tabs->addTab(view, title);
    m_tabs->setCurrentIndex(idx);

    // 讓 statusbar 顯示即時更新
    attachStatusToView(view);
    setCurrentFile(view, fileName);
    return idx;
}

void HexForm::setCurrentFile(QWidget* page, const QString &fileName) {
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
        setWindowFilePath("Hexadecimal Editor");
        setWindowTitle("Hexadecimal Editor");
    }
    else {
        setWindowFilePath(canonical + " - Hexadecimal Editor");
        setWindowTitle(QFileInfo(canonical).fileName() + " - Hexadecimal Editor");
    }
}

bool HexForm::saveFile(QWidget* page, const QString &fileName) {
    HexView* view = qobject_cast<HexView*>(page);
    if (!view) return false;

    QString tmpFileName = fileName + ".~tmp";

    QApplication::setOverrideCursor(Qt::WaitCursor);
    QFile file(tmpFileName);
    bool ok = view->saveToFile(tmpFileName);
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
            emit view->modifiedChanged(false);
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
    statusBar()->showMessage(tr("File saved"), 2000);
    return true;
}

void HexForm::closeTabAt(int index)
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

void HexForm::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);

    // 視窗大小改變 → 讓 TabWidget 填滿 hexViewWidget
    if (m_tabs)
        m_tabs->setGeometry(ui->hexViewWidget->rect());
}

void HexForm::showEvent(QShowEvent *event)
{
    QWidget::showEvent(event);

    if (m_tabs)
        m_tabs->setGeometry(ui->hexViewWidget->rect());
}

// -------------------- Drag & Drop --------------------

void HexForm::dragEnterEvent(QDragEnterEvent *event)
{
    if (event->mimeData() && event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
        return;
    }
    QMainWindow::dragEnterEvent(event);
}

void HexForm::dropEvent(QDropEvent *event)
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

void HexForm::setAddress(qint64 address) {
    HexView* view = currentHexView();
    if (!view) return;
    lineEditAddress->setText(QString("%1").arg(address, view->getaddressChars(), 16, QLatin1Char('0')).toUpper());
}

void HexForm::setSize(qint64 size) {
    // lineEditSize->setText(QString("%1").arg(size, 1).toUpper());
    this->changeSizeUnit(cbSizeUnit->currentIndex(), size);
}

void HexForm::create() {
    // 初始的 device 也放進第一個 tab
    QString initialName;
    QIODevice *dev = nullptr;
    if (auto *qf = qobject_cast<QFile*>(dev)) {
        initialName = qf->fileName();
    }
    addHexTab(dev, initialName, true);
}

void HexForm::open() {
    QSettings settings;
    QString lastDir = settings.value("LastDir", QDir::homePath()).toString();

    QString fileName = QFileDialog::getOpenFileName(this, tr("Open"), lastDir);
    if (!fileName.isEmpty()) {
        settings.setValue("LastDir", QFileInfo(fileName).absolutePath());
        openFileInNewTab(fileName);
    }
}

void HexForm::openFileInNewTab(const QString& fileName) {
    if (fileName.isEmpty())
        return;

    QFile *file = new QFile(fileName, this);
    int idx = addHexTab(file, fileName, true);
    QWidget* page = m_tabs->widget(idx);
    file->setParent(page);

    statusBar()->showMessage(tr("File loaded..."), 2000);
}

bool HexForm::save() {
    QWidget* page = currentPage();
    if (!page) return false;

    const bool isUntitled = page->property("isUntitled").toBool();
    const QString curFile = page->property("curFile").toString();

    if (isUntitled)
        return saveAs();
    else
        return saveFile(page, curFile);
}

bool HexForm::saveAs() {
    QWidget* page = currentPage();
    if (!page) return false;

    const QString curFile = page->property("curFile").toString();
    QString fileName = QFileDialog::getSaveFileName(this, tr("Save As"), curFile);
    if (fileName.isEmpty())
        return false;

    return saveFile(page, fileName);
}

void HexForm::dataChanged() {
    QWidget* page = currentPage();
    if (!page) return;

    page->setProperty("isModified", true);
    setWindowModified(true);
}

void HexForm::shortcutKeyHelper() {
    HexShortcutDialog dlg(this);
    dlg.exec();
}

// -------------------- Close Tab Ask Save --------------------

bool HexForm::maybeSaveTab(int index)
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

void HexForm::showTabSwitcher(bool reverse)
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

void HexForm::changeSizeUnit(int idx, qint64 size) {
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
