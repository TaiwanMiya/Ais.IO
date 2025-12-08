// #include "base_encoder_window.h"
#include "../include/launcher_window.h"
#include "../include/config.h"

#include <QApplication>
#include <QStyleHints>
#include <QPalette>
#include <QLocale>
#include <QTranslator>

static QPalette makeDarkPalette() {
    QPalette p;
    p.setColor(QPalette::Window, QColor(0x2b,0x2b,0x2b));
    p.setColor(QPalette::Base,   QColor(0x1e,0x1e,0x1e));
    p.setColor(QPalette::AlternateBase, QColor(0x25,0x25,0x25));
    p.setColor(QPalette::Text,   Qt::white);
    p.setColor(QPalette::WindowText, Qt::white);
    p.setColor(QPalette::Button, QColor(0x3c,0x3f,0x41));
    p.setColor(QPalette::ButtonText, Qt::white);
    p.setColor(QPalette::ToolTipBase, QColor(0x33,0x33,0x33));
    p.setColor(QPalette::ToolTipText, Qt::white);
    p.setColor(QPalette::Highlight, QColor(0x00,0x7a,0xcc));
    p.setColor(QPalette::HighlightedText, Qt::white);
    p.setColor(QPalette::PlaceholderText, QColor(255,255,255,128));
    return p;
}

static void applyTheme(ThemeMode mode,
                       const QPalette& systemLight,
                       const QPalette& systemDarkCandidate = QPalette()) {
    auto setDark = [&]{
        QApplication::setPalette(makeDarkPalette());
    };
    auto setLight = [&]{
        QApplication::setPalette(systemLight); // 原生/淺色
    };

    switch (mode) {
    case ThemeMode::Dark:  setDark();  break;
    case ThemeMode::Light: setLight(); break;
    case ThemeMode::System:
    default: setDark();  break;
    }
}

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    app.setWindowIcon(QIcon(":/images/aisio-icon.png"));
    Config::instance().load();

    const QPalette systemLight = QApplication::palette();
    applyTheme(Config::instance().themeMode(), systemLight);
#if QT_VERSION >= QT_VERSION_CHECK(6,5,0)
    // 若 user 選 system：跟著系統即時切換
    QObject::connect(qApp->styleHints(), &QStyleHints::colorSchemeChanged,
                     [&](Qt::ColorScheme cs){
                         if (Config::instance().themeMode() == ThemeMode::System) {
                             applyTheme(ThemeMode::System, systemLight);
                         }
                     });
#endif

    QTranslator translator;
    const QStringList uiLanguages = QLocale::system().uiLanguages();
    for (const QString &locale : uiLanguages) {
        const QString baseName = "aisio-gui_" + QLocale(locale).name();
        if (translator.load(":/i18n/" + baseName)) {
            app.installTranslator(&translator);
            break;
        }
    }
    LauncherWindow w;
    w.show();
    return app.exec();
}
