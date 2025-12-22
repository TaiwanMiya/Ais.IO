#ifndef TEXTVIEW_H
#define TEXTVIEW_H

#pragma once
#include <QPlainTextEdit>
#include <QWidget>
#include <QPainter>

class LineNumberArea;

class TextView : public QPlainTextEdit {
    Q_OBJECT

public:
    TextView(QWidget *parent = nullptr);
    int lineNumberAreaWidth();
    void lineNumberAreaPaintEvent(QPaintEvent *event);

protected:
    void resizeEvent(QResizeEvent *event) override;

private slots:
    void updateLineNumberAreaWidth(int newBlockCount);
    void highlightCurrentLine();
    void paintEvent(QPaintEvent *event);
    void updateLineNumberArea(const QRect &, int);

private:
    QWidget *lineNumberArea;
};

class LineNumberArea : public QWidget {
public:
    LineNumberArea(TextView *editor) : QWidget(editor), codeEditor(editor) {}
    QSize sizeHint() const override { return QSize(codeEditor->lineNumberAreaWidth(), 0); }

protected:
    void paintEvent(QPaintEvent *event) override { codeEditor->lineNumberAreaPaintEvent(event); }

private:
    TextView *codeEditor;
};


#endif // CODEEDITOR_H
