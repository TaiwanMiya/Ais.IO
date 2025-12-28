#ifndef INTERPRETVALUEDELEGATE_H
#define INTERPRETVALUEDELEGATE_H

#include <QEvent>
#include <QKeyEvent>
#include <QLineEdit>
#include <QString>
#include <QStyledItemDelegate>

namespace {

static QString stripBytesSuffix(QString s)
{
    s = s.trimmed();
    // 移除尾端像 "  (1 byte)" / "  (12 bytes)" 這種
    int p = s.lastIndexOf(" (");
    if (p > 0) s = s.left(p).trimmed();
    return s;
}

class InterpretValueDelegate final : public QStyledItemDelegate
{
public:
    explicit InterpretValueDelegate(QObject* parent = nullptr)
        : QStyledItemDelegate(parent) {}

    bool enterCommit() const { return m_enterCommit; }

private:
    mutable bool m_enterCommit = false;

    QWidget* createEditor(QWidget* parent,
                          const QStyleOptionViewItem& option,
                          const QModelIndex& index) const override
    {
        QWidget* ed = QStyledItemDelegate::createEditor(parent, option, index);
        if (ed) ed->installEventFilter(const_cast<InterpretValueDelegate*>(this));
        return ed;
    }

    void setEditorData(QWidget* editor, const QModelIndex& index) const override
    {
        auto* le = qobject_cast<QLineEdit*>(editor);
        if (!le) return;

        m_enterCommit = false;   // ⭐ 每次進入編輯先重置

        QString raw = index.data(Qt::UserRole).toString().trimmed();
        if (raw.isEmpty())
            raw = stripBytesSuffix(index.data(Qt::DisplayRole).toString());

        le->setText(raw);
        le->selectAll();
    }

    bool eventFilter(QObject* obj, QEvent* ev) override
    {
        auto* le = qobject_cast<QLineEdit*>(obj);
        if (!le) return QStyledItemDelegate::eventFilter(obj, ev);

        if (ev->type() == QEvent::KeyPress) {
            auto* ke = static_cast<QKeyEvent*>(ev);
            if (ke->key() == Qt::Key_Return || ke->key() == Qt::Key_Enter) {
                m_enterCommit = true;
                emit commitData(le);
                emit closeEditor(le, QAbstractItemDelegate::SubmitModelCache);
                return true;
            }
            if (ke->key() == Qt::Key_Escape) {
                m_enterCommit = false;
                emit closeEditor(le, QAbstractItemDelegate::RevertModelCache);
                return true;
            }
        }

        if (ev->type() == QEvent::FocusOut) {
            m_enterCommit = false;
            emit closeEditor(le, QAbstractItemDelegate::RevertModelCache);
            return true;
        }

        return QStyledItemDelegate::eventFilter(obj, ev);
    }
};

} // namespace

#endif // INTERPRETVALUEDELEGATE_H
