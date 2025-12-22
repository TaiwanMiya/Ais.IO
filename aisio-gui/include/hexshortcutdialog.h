#ifndef HEXSHORTCUTDIALOG_H
#define HEXSHORTCUTDIALOG_H

#include <QDialog>
#include <QTableView>
#include <QLineEdit>
#include <QStandardItemModel>
#include <QSortFilterProxyModel>

class HexShortcutDialog : public QDialog
{
    Q_OBJECT
public:
    explicit HexShortcutDialog(QWidget *parent = nullptr);

private:
    void setupUi();
    void populateData();

    QLineEdit *searchEdit;
    QTableView *tableView;
    QStandardItemModel *model;
    QSortFilterProxyModel *proxyModel;
};

#endif // HEXSHORTCUTDIALOG_H
