#ifndef RICHTEXTDELEGATE_H
#define RICHTEXTDELEGATE_H

#include <QStyledItemDelegate>
#include <QTextDocument>
#include <QPainter>

class RichTextDelegate : public QStyledItemDelegate {
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter *painter,
               const QStyleOptionViewItem &option,
               const QModelIndex &index) const override {
        QString text = index.data(Qt::DisplayRole).toString();

        // 沒有 HTML → 用預設繪製
        if (!text.contains('<') && !text.contains('>')) {
            QStyledItemDelegate::paint(painter, option, index);
            return;
        }

        // 讓背景、選取效果仍然正常
        QStyleOptionViewItem opt(option);
        initStyleOption(&opt, index);

        painter->save();

        // 先畫 item 背景（含 selection）
        opt.text.clear();
        opt.widget->style()->drawControl(QStyle::CE_ItemViewItem, &opt, painter, opt.widget);

        // 再畫 HTML
        QTextDocument doc;
        doc.setDefaultFont(option.font);
        doc.setHtml(text);
        painter->translate(opt.rect.topLeft());
        doc.drawContents(painter);
        painter->restore();
    }

    QSize sizeHint(const QStyleOptionViewItem &option,
                   const QModelIndex &index) const override {
        QString text = index.data(Qt::DisplayRole).toString();

        if (!text.contains('<') && !text.contains('>'))
            return QStyledItemDelegate::sizeHint(option, index);

        QTextDocument doc;
        doc.setDefaultFont(option.font);
        doc.setHtml(text);
        return QSize(doc.idealWidth(), option.fontMetrics.height());
    }
};

#endif // RICHTEXTDELEGATE_H
