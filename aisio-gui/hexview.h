#ifndef HEXVIEW_H
#define HEXVIEW_H

#include <QWidget>
#include <QTableWidget>
#include <QByteArray>
#include <QFontDatabase>

class HexView : public QWidget
{
    Q_OBJECT
public:
    explicit HexView(QWidget *parent = nullptr);

    // 外部讀取資料的介面
    void setEditable(bool enabled = true);
    void loadData(const QByteArray &data, QFontDatabase::SystemFont setFont = QFontDatabase::FixedFont);

    // 跳到 offset
    void gotoOffset(qint64 offset);

    // 搜尋
    qint64 findHex(const QByteArray &hexBytes, qint64 start = 0);
    qint64 findText(const QString &text, qint64 start = 0);

signals:
    void offsetSelected(qint64 offset); //（點選 cell 時通知父 GUI）

private:
    QTableWidget *table;
    QByteArray buffer;     // ← 真正的資料
    bool editable = false;

    void setupTable();

    // 高亮 Hex/ASCII
    void highlightOffset(qint64 offset);

private slots:
    void onCellClicked(int row, int col);
    void onCellEdited(int row, int col);
};

#endif // HEXVIEW_H
