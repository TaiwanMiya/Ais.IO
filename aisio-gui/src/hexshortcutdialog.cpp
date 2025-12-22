#include "../include/hexshortcutdialog.h"

#include <QVBoxLayout>
#include <QHeaderView>
#include <QFontDatabase>
#include <QPushButton>

HexShortcutDialog::HexShortcutDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Shortcut key instructions"));
    resize(640, 360);

    setupUi();
    populateData();
}

void HexShortcutDialog::setupUi()
{
    this->setStyleSheet(R"(/* Shortcut Dialog 本體 */
QDialog {
    background-color: #1f1f1f;
    color: #e8e8e8;
}

/* 搜尋框（會吃你現有 QLineEdit，但可微調） */
QDialog QLineEdit {
    background-color: #1e1e1e;
    color: #e0e0e0;
    border: 1px solid #3a3f4b;
    border-radius: 6px;
    padding: 6px;
}

/* TableView 本體 */
QTableView {
    background-color: #1e1e1e;
    color: #dfe3ea;
    gridline-color: #2a2f39;
    border: 1px solid #343a46;
    border-radius: 6px;
    selection-background-color: #394359;
    selection-color: #ffffff;
}

/* 表頭（VSCode 很重要的一塊） */
QHeaderView::section {
    background-color: #2b2f3a;
    color: #eaeaea;
    padding: 6px;
    border: none;
    border-bottom: 1px solid #3a3f4b;
    font-weight: 500;
}

/* 滑過列 */
QTableView::item:hover {
    background-color: #2a2f39;
}

/* 選取列 */
QTableView::item:selected {
    background-color: #394359;
}

/* 捲軸（簡約版） */
QScrollBar:vertical {
    background: #1f1f1f;
    width: 10px;
}
QScrollBar::handle:vertical {
    background: #3a3f4b;
    border-radius: 4px;
}
QScrollBar::handle:vertical:hover {
    background: #505357;
})");

    auto *layout = new QVBoxLayout(this);

    // 🔍 搜尋列
    searchEdit = new QLineEdit(this);
    searchEdit->setPlaceholderText(tr("Search actions or shortcuts"));
    layout->addWidget(searchEdit);

    // 📋 Model
    model = new QStandardItemModel(this);
    model->setColumnCount(2);
    model->setHeaderData(0, Qt::Horizontal, tr("Action"));
    model->setHeaderData(1, Qt::Horizontal, tr("Shortcut keys"));

    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(model);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterKeyColumn(-1); // 全欄搜尋

    // 🧾 TableView
    tableView = new QTableView(this);
    tableView->setModel(proxyModel);
    tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableView->setSelectionMode(QAbstractItemView::SingleSelection);
    tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tableView->verticalHeader()->hide();
    tableView->horizontalHeader()->setStretchLastSection(true);
    tableView->setAlternatingRowColors(false);
    tableView->verticalHeader()->setDefaultSectionSize(24);
    tableView->setShowGrid(false);

    auto *header = tableView->horizontalHeader();
    header->setSectionResizeMode(0, QHeaderView::Stretch);
    header->setSectionResizeMode(1, QHeaderView::Fixed);
    tableView->setColumnWidth(1, 180);

    // 等寬字顯示快捷鍵欄
    QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    tableView->setFont(mono);

    layout->addWidget(tableView);

    // ❌ 關閉按鈕
    auto *closeBtn = new QPushButton(tr("Close"), this);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);
    layout->addWidget(closeBtn, 0, Qt::AlignCenter);

    // 🔗 搜尋連動
    connect(searchEdit, &QLineEdit::textChanged,
            proxyModel, &QSortFilterProxyModel::setFilterFixedString);
}

void HexShortcutDialog::populateData()
{
    auto addRow = [&](const QString &action, const QString &key) {
        QList<QStandardItem*> row;
        row << new QStandardItem(action)
            << new QStandardItem(key);
        model->appendRow(row);
    };

    // 🧭 游標與選取
    addRow("Cursor selection", "Left mouse button");
    addRow("Multiple selection of cursors", "Hold down the left mouse button");
    addRow("Cursor up", "↑");
    addRow("Cursor down", "↓");
    addRow("Cursor left", "←");
    addRow("Cursor right", "→");
    addRow("Previous page", "PageUp");
    addRow("Next page", "PageDown");
    addRow("Move to the beginning of the line", "Home");
    addRow("Move to the end of the line", "End");
    addRow("Move to the beginning of the file", "Ctrl + Home");
    addRow("Move to the end of the file", "Ctrl + End");
    addRow("Select up", "Shift + ↑");
    addRow("Select down", "Shift + ↓");
    addRow("Select left", "Shift + ←");
    addRow("Select right", "Shift + →");
    addRow("Select to previous page", "Shift + PageUp");
    addRow("Select to next page", "Shift + PageDown");
    addRow("Select to the beginning of the line", "Shift + Home");
    addRow("Select to the end of the line", "Shift + End");
    addRow("Select to the beginning of the file", "Ctrl + Shift + Home");
    addRow("Select to the end of the file", "Ctrl + Shift + End");
    addRow("Select all", "Ctrl + A");
    addRow("Cancel selection", "Esc");

    // ✏️ 編輯
    addRow("Insert a byte (0x00)", "Insert");
    addRow("Delete selected byte", "Delete");
    addRow("Delete the previous byte", "Backspace");
    addRow("Copy", "Ctrl + C");
    addRow("Paste", "Ctrl + V");
    addRow("Undo", "Ctrl + Z");
    addRow("Redo", "Ctrl + Y");

    // 🔍 搜索
    addRow("Search Hex / ASCII", "Ctrl + F");
    addRow("Next search result", "F3");
    addRow("Previous search result", "Shift + F3");
    addRow("Goto offset", "Ctrl + G");
}
