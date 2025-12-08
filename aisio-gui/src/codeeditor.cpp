#include "../include/codeeditor.h"
#include <QRegularExpressionMatchIterator>
#include <QTextBlock>
#include <QTextFormat>

CodeEditor::CodeEditor(QWidget *parent) : QPlainTextEdit(parent) {
    lineNumberArea = new LineNumberArea(this);

    connect(this, &CodeEditor::blockCountChanged, this, &CodeEditor::updateLineNumberAreaWidth);
    connect(this, &CodeEditor::updateRequest, this, &CodeEditor::updateLineNumberArea);
    connect(this, &CodeEditor::cursorPositionChanged, this, &CodeEditor::highlightCurrentLine);

    updateLineNumberAreaWidth(0);
    highlightCurrentLine();
}

int CodeEditor::lineNumberAreaWidth() {
    int digits = 1;
    int max = qMax(1, blockCount());
    while (max >= 10) {
        max /= 10;
        ++digits;
    }
    int space = 3 + fontMetrics().horizontalAdvance(QLatin1Char('9')) * digits;
    return space;
}

void CodeEditor::updateLineNumberAreaWidth(int /* newBlockCount */) {
    setViewportMargins(lineNumberAreaWidth(), 0, 0, 0);
}

void CodeEditor::updateLineNumberArea(const QRect &rect, int dy) {
    if (dy)
        lineNumberArea->scroll(0, dy);
    else
        lineNumberArea->update(0, rect.y(), lineNumberArea->width(), rect.height());

    if (rect.contains(viewport()->rect()))
        updateLineNumberAreaWidth(0);
}

void CodeEditor::resizeEvent(QResizeEvent *e) {
    QPlainTextEdit::resizeEvent(e);
    QRect cr = contentsRect();
    lineNumberArea->setGeometry(QRect(cr.left(), cr.top(), lineNumberAreaWidth(), cr.height()));
}

void CodeEditor::lineNumberAreaPaintEvent(QPaintEvent *event) {
    QPainter painter(lineNumberArea);
    painter.fillRect(event->rect(), QColor(40, 44, 52)); // VSCode風格深灰背景

    QTextBlock block = firstVisibleBlock();
    int blockNumber = block.blockNumber();
    int top = static_cast<int>(blockBoundingGeometry(block).translated(contentOffset()).top());
    int bottom = top + static_cast<int>(blockBoundingRect(block).height());

    while (block.isValid() && top <= event->rect().bottom()) {
        if (block.isVisible() && bottom >= event->rect().top()) {
            QString number = QString::number(blockNumber + 1);
            painter.setPen(Qt::lightGray);
            painter.drawText(0, top, lineNumberArea->width() - 4, fontMetrics().height(),
                             Qt::AlignRight, number);
        }

        block = block.next();
        top = bottom;
        bottom = top + static_cast<int>(blockBoundingRect(block).height());
        ++blockNumber;
    }
}

void CodeEditor::highlightCurrentLine() {
    if (!isReadOnly()) {
        QList<QTextEdit::ExtraSelection> extraSelections;
        QTextEdit::ExtraSelection selection;
        QColor lineColor = QColor(56, 60, 74); // 深色高亮背景
        selection.format.setBackground(lineColor);
        selection.format.setProperty(QTextFormat::FullWidthSelection, true);
        selection.cursor = textCursor();
        selection.cursor.clearSelection();
        extraSelections.append(selection);
        setExtraSelections(extraSelections);
    }
}

void CodeEditor::paintEvent(QPaintEvent *event) {
    QPlainTextEdit::paintEvent(event);

    QPainter painter(viewport());
    painter.setRenderHint(QPainter::TextAntialiasing);
    painter.setRenderHint(QPainter::Antialiasing);
    QTextBlock block = firstVisibleBlock();
    int top = static_cast<int>(blockBoundingGeometry(block).translated(contentOffset()).top());

    while (block.isValid() && top <= event->rect().bottom()) {
        QString text = block.text().trimmed();

        // 找出所有類型標記，例如 -int, -float, -string ...
        QRegularExpression re("-(int|float|double|string)");
        QRegularExpressionMatchIterator i = re.globalMatch(text);
        while (i.hasNext()) {
            QRegularExpressionMatch match = i.next();
            QString type = match.captured(1);
            int startPos = match.capturedStart(0);

            // 找出該文字位置的像素座標
            QTextCursor cursor(block);
            cursor.setPosition(block.position() + startPos);
            QRect cursorR = cursorRect(cursor);

            // 決定顏色
            QColor fillColor, textColor(0x96, 0xc8, 0xff);
            QRect rect;
            if (type == "int") {
                fillColor = QColor(0x80, 0x00, 0xff);
                textColor = QColor(0xfc, 0xfc, 0xfc);
                rect = QRect(cursorR.left(), top + 2, 18, fontMetrics().height() - 2);
            }
            else if (type == "float") {
                fillColor = QColor(0xff, 0x2d, 0x2d);
                textColor = QColor(0xfc, 0xfc, 0xfc);
                rect = QRect(cursorR.left(), top + 2, 30, fontMetrics().height() - 2);
            }
            else if (type == "double") {
                fillColor = QColor(0xf9, 0xf9, 0x00);
                textColor = QColor(0x27, 0x27, 0x27);
                rect = QRect(cursorR.left(), top + 2, 45, fontMetrics().height() - 2);
            }
            else if (type == "string") {
                fillColor = QColor(0x28, 0x28, 0xff);
                textColor = QColor(0xfc, 0xfc, 0xfc);
                rect = QRect(cursorR.left(), top + 2, 34, fontMetrics().height() - 2);
            }
            int boxWidth = fontMetrics().horizontalAdvance(type) + 5;
            int boxHeight = fontMetrics().height() - 2;
            rect = QRect(cursorR.left(), cursorR.top(), boxWidth, boxHeight);

            painter.setBrush(fillColor);
            painter.setPen(textColor);
            painter.drawRoundedRect(rect, 1, 1);
            painter.setPen(textColor);
            painter.drawText(rect, Qt::AlignCenter, type);
        }

        block = block.next();
        top += static_cast<int>(blockBoundingRect(block).height());
    }
}
