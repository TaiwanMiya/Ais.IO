/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 6.9.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QLocale>
#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenu>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QAction *actionBase;
    QWidget *centralwidget;
    QTextEdit *plainText;
    QTextEdit *cipherText;
    QPushButton *decodeButton;
    QPushButton *encodeButton;
    QComboBox *modeComboBox;
    QMenuBar *menubar;
    QMenu *menuBase_Encoder;
    QMenu *menuAES;
    QMenu *menuDES;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName("MainWindow");
        MainWindow->resize(1280, 720);
        QSizePolicy sizePolicy(QSizePolicy::Policy::Preferred, QSizePolicy::Policy::Preferred);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(MainWindow->sizePolicy().hasHeightForWidth());
        MainWindow->setSizePolicy(sizePolicy);
        MainWindow->setFocusPolicy(Qt::FocusPolicy::StrongFocus);
        MainWindow->setAutoFillBackground(true);
        MainWindow->setStyleSheet(QString::fromUtf8("font: 700 12pt \"Arial Rounded MT\";"));
        MainWindow->setLocale(QLocale(QLocale::English, QLocale::UnitedStates));
        actionBase = new QAction(MainWindow);
        actionBase->setObjectName("actionBase");
        centralwidget = new QWidget(MainWindow);
        centralwidget->setObjectName("centralwidget");
        plainText = new QTextEdit(centralwidget);
        plainText->setObjectName("plainText");
        plainText->setGeometry(QRect(40, 80, 500, 500));
        cipherText = new QTextEdit(centralwidget);
        cipherText->setObjectName("cipherText");
        cipherText->setGeometry(QRect(740, 80, 500, 500));
        cipherText->setFocusPolicy(Qt::FocusPolicy::WheelFocus);
        decodeButton = new QPushButton(centralwidget);
        decodeButton->setObjectName("decodeButton");
        decodeButton->setGeometry(QRect(590, 350, 101, 41));
        encodeButton = new QPushButton(centralwidget);
        encodeButton->setObjectName("encodeButton");
        encodeButton->setGeometry(QRect(590, 260, 101, 41));
        modeComboBox = new QComboBox(centralwidget);
        modeComboBox->addItem(QString());
        modeComboBox->addItem(QString());
        modeComboBox->addItem(QString());
        modeComboBox->addItem(QString());
        modeComboBox->addItem(QString());
        modeComboBox->addItem(QString());
        modeComboBox->addItem(QString());
        modeComboBox->addItem(QString());
        modeComboBox->setObjectName("modeComboBox");
        modeComboBox->setGeometry(QRect(590, 80, 101, 31));
        modeComboBox->setAutoFillBackground(false);
        MainWindow->setCentralWidget(centralwidget);
        menubar = new QMenuBar(MainWindow);
        menubar->setObjectName("menubar");
        menubar->setGeometry(QRect(0, 0, 1280, 24));
        menuBase_Encoder = new QMenu(menubar);
        menuBase_Encoder->setObjectName("menuBase_Encoder");
        menuAES = new QMenu(menubar);
        menuAES->setObjectName("menuAES");
        menuDES = new QMenu(menubar);
        menuDES->setObjectName("menuDES");
        MainWindow->setMenuBar(menubar);
        statusbar = new QStatusBar(MainWindow);
        statusbar->setObjectName("statusbar");
        MainWindow->setStatusBar(statusbar);

        menubar->addAction(menuBase_Encoder->menuAction());
        menubar->addAction(menuAES->menuAction());
        menubar->addAction(menuDES->menuAction());

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QCoreApplication::translate("MainWindow", "Ais IO Tools", nullptr));
        actionBase->setText(QCoreApplication::translate("MainWindow", "Base", nullptr));
#if QT_CONFIG(whatsthis)
        plainText->setWhatsThis(QString());
#endif // QT_CONFIG(whatsthis)
#if QT_CONFIG(accessibility)
        plainText->setAccessibleDescription(QString());
#endif // QT_CONFIG(accessibility)
        decodeButton->setText(QCoreApplication::translate("MainWindow", "Decode", nullptr));
        encodeButton->setText(QCoreApplication::translate("MainWindow", "Encode", nullptr));
        modeComboBox->setItemText(0, QCoreApplication::translate("MainWindow", "Base10", nullptr));
        modeComboBox->setItemText(1, QCoreApplication::translate("MainWindow", "Base16", nullptr));
        modeComboBox->setItemText(2, QCoreApplication::translate("MainWindow", "Base32", nullptr));
        modeComboBox->setItemText(3, QCoreApplication::translate("MainWindow", "Base58", nullptr));
        modeComboBox->setItemText(4, QCoreApplication::translate("MainWindow", "Base62", nullptr));
        modeComboBox->setItemText(5, QCoreApplication::translate("MainWindow", "Base64", nullptr));
        modeComboBox->setItemText(6, QCoreApplication::translate("MainWindow", "Base85", nullptr));
        modeComboBox->setItemText(7, QCoreApplication::translate("MainWindow", "Base91", nullptr));

        menuBase_Encoder->setTitle(QCoreApplication::translate("MainWindow", "Base Encoder", nullptr));
        menuAES->setTitle(QCoreApplication::translate("MainWindow", "AES", nullptr));
        menuDES->setTitle(QCoreApplication::translate("MainWindow", "DES", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
