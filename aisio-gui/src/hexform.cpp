#include "../include/hexform.h"
#include "../include/hexview.h"
#include "ui_hexform.h"

#include <QComboBox>
#include <QLineEdit>
#include <QShortcut>
#include <QToolButton>
#include <QApplication>
#include <QRegularExpression>

HexForm::HexForm(const QByteArray &arr, QWidget *parent, bool setEdit)
    : QWidget(parent)
    , ui(new Ui::HexForm) {

    ui->setupUi(this);

    // ⭐ 改：讓 searchBar 浮動在 HexForm，而不是 layout 裡
    ui->searchBarWidget->setParent(this);
    ui->searchBarWidget->hide();

    m_hexView = new HexView(ui->hexViewWidget);
    m_hexView->setGeometry(ui->hexViewWidget->rect());
    m_hexView->show();

    m_hexView->loadData(arr);
    m_hexView->setEditable(setEdit);
    this->EnabledConnect();
}

HexForm::~HexForm() {
    delete ui;
}

void HexForm::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);

    // ⭐ 讓 HexView 填滿 hexViewWidget
    if (m_hexView)
        m_hexView->setGeometry(ui->hexViewWidget->rect());

    // ⭐ searchBar 可以保持距離
    positionSearchBar();
}

void HexForm::showEvent(QShowEvent *event)
{
    QWidget::showEvent(event);

    if (m_hexView)
        m_hexView->setGeometry(ui->hexViewWidget->rect());

    positionSearchBar();
}

void HexForm::setupShortcuts() {
    // Ctrl+F: 聚焦搜尋欄
    QShortcut *scFind = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_F), this);
    connect(scFind, &QShortcut::activated, this, [this]{
        toggleSearchBar(true);
        ui->lineEditFind->setFocus();
        ui->lineEditFind->selectAll();
    });

    // F3: Next
    QShortcut *scNext = new QShortcut(QKeySequence(Qt::Key_F3), this);
    connect(scNext, &QShortcut::activated, this, [this] {
        toggleSearchBar(true);
        onFindNext();
    });

    // Shift+F3: Prev
    QShortcut *scPrev = new QShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F3), this);
    connect(scPrev, &QShortcut::activated, this, [this] {
        toggleSearchBar(true);
        onFindPrev();
    });

    // Ctrl+G: Go To Offset
    QShortcut *scGoto = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_G), this);
    connect(scGoto, &QShortcut::activated, this, [this] {
        toggleSearchBar(true);
        focusGotoBox();
    });

    QShortcut *scEsc = new QShortcut(QKeySequence(Qt::Key_Escape), this);
    scEsc->setContext(Qt::WidgetShortcut);
    connect(scEsc, &QShortcut::activated, this, [this]{

        QWidget* f = QApplication::focusWidget();

        // 若焦點在搜尋區塊內 → 關閉
        if (ui->searchBarWidget->isVisible() &&
            (f == ui->lineEditFind || f == ui->comboFindMode ||
             f == ui->btnFindNext   || f == ui->btnFindPrev ||
             f == ui->lineEditGoto  || f == ui->btnGoto))
        {
            toggleSearchBar(false);
            return; // ⚠️ 這時吃掉 ESC
            // m_hexView->setFocus();
        }
    });
}

QByteArray HexForm::parseHexString(const QString &s, bool *ok) const {
    QString text = s.trimmed();
    if (text.startsWith("0x") || text.startsWith("0X"))
        text = text.mid(2);

    // 去掉所有空白
    text.remove(QRegularExpression("\\s+"));

    if (text.isEmpty()) {
        if (ok) *ok = false;
        return QByteArray();
    }

    if (text.size() % 2 != 0) {
        // 奇數長度，不合法
        if (ok) *ok = false;
        return QByteArray();
    }

    QByteArray result;
    result.reserve(text.size() / 2);

    for (int i = 0; i < text.size(); i += 2) {
        bool byteOk = false;
        int val = text.mid(i, 2).toInt(&byteOk, 16);
        if (!byteOk || val < 0 || val > 0xFF) {
            if (ok) *ok = false;
            return QByteArray();
        }
        result.append(char(val));
    }
    if (ok) *ok = true;
    return result;
}

qint64 HexForm::doFind(bool backwards, bool newPattern) {
    QString input = ui->lineEditFind->text();
    if (input.isEmpty())
        return -1;

    QByteArray pattern;
    if (m_findMode == FindMode::Hex) {
        bool ok = false;
        pattern = parseHexString(input, &ok);
        if (!ok || pattern.isEmpty())
            return -1;
    } else {
        // Text 模式：直接 utf-8 bytes
        pattern = input.toUtf8();
        if (pattern.isEmpty())
            return -1;
    }

    qint64 start = 0;
    if (!newPattern && m_lastPos >= 0) {
        start = backwards ? (m_lastPos - 1) : m_lastPos;
        if (start < 0) start = 0;
    } else {
        // 新 pattern 從目前選取位置之後開始
        // 嘗試抓目前光標的 offset
        // auto idx = m_hexView->currentIndex(); // 若你有 m_hexView，用 m_hexView->currentIndex 之類
        // // 這裡簡化：先從 0 開始
        // start = m_hexView->offsetFromIndex(idx);
        if (start < 0) start = 0;
    }

    qint64 pos = m_hexView->findBytes(pattern, start, backwards);
    if (pos >= 0) {
        m_lastPattern = pattern;
        m_lastPos = pos + (backwards ? 0 : pattern.size());
    }
    return pos;
}

void HexForm::EnabledConnect() {
    // 搜尋模式 combo
    connect(ui->comboFindMode, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &HexForm::onFindModeChanged);

    // Find 文字改變時，重置狀態
    connect(ui->lineEditFind, &QLineEdit::textEdited,
            this, &HexForm::onFindTextEdited);

    // Next / Prev 按鈕
    connect(ui->lineEditFind, &QLineEdit::returnPressed,
            this, &HexForm::onFindNext);
    connect(ui->btnFindNext, &QToolButton::clicked,
            this, &HexForm::onFindNext);
    connect(ui->btnFindPrev, &QToolButton::clicked,
            this, &HexForm::onFindPrev);

    // Go To
    connect(ui->btnGoto, &QToolButton::clicked,
            this, &HexForm::onGotoOffset);
    connect(ui->lineEditGoto, &QLineEdit::returnPressed,
            this, &HexForm::onGotoOffset);

    setupShortcuts();
}

void HexForm::positionSearchBar()
{
    // 浮在畫面上方 8px 的位置
    ui->searchBarWidget->move(8, 8);
    ui->searchBarWidget->raise();
}

void HexForm::onFindModeChanged(int index) {
    m_findMode = (index == 1) ? FindMode::Text : FindMode::Hex;
    m_lastPattern.clear();
    m_lastPos = -1;
}

void HexForm::onFindTextEdited() {
    m_lastPattern.clear();
    m_lastPos = -1;
}

void HexForm::onFindNext() {
    bool newPattern = m_lastPattern.isEmpty() ||
                      (m_findMode == FindMode::Hex
                           ? (parseHexString(ui->lineEditFind->text(), nullptr) != m_lastPattern)
                           : (ui->lineEditFind->text().toUtf8() != m_lastPattern));

    doFind(false, newPattern);
}

void HexForm::onFindPrev() {
    bool newPattern = m_lastPattern.isEmpty() ||
                      (m_findMode == FindMode::Hex
                           ? (parseHexString(ui->lineEditFind->text(), nullptr) != m_lastPattern)
                           : (ui->lineEditFind->text().toUtf8() != m_lastPattern));

    doFind(true, newPattern);
}

void HexForm::onGotoOffset() {
    QString t = ui->lineEditGoto->text().trimmed();
    if (t.isEmpty())
        return;

    bool ok = false;
    qint64 value = 0;

    if (t.startsWith("0x") || t.startsWith("0X")) {
        value = t.mid(2).toLongLong(&ok, 16);
    } else {
        // 有 A-F 代表是 hex，純數字當 10 進位
        if (t.contains(QRegularExpression("[A-Fa-f]")))
            value = t.toLongLong(&ok, 16);
        else
            value = t.toLongLong(&ok, 10);
    }

    if (!ok || value < 0)
        return;

    m_hexView->gotoOffset(value);
}

void HexForm::focusGotoBox() {
    ui->lineEditGoto->setFocus();
    ui->lineEditGoto->selectAll();
}

void HexForm::toggleSearchBar(bool show) {
    ui->searchBarWidget->setVisible(show);

    if (show) {
        positionSearchBar();
        ui->lineEditFind->setFocus();
        ui->lineEditFind->selectAll();
    }
}
