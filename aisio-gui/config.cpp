#include "config.h"
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QSaveFile>
#include <QJsonDocument>
#include <QResource>

static const char* kResDefault = ":/config/default.json";
static const char* kUserFile   = "app.json";

Config& Config::instance() {
    static Config inst;
    return inst;
}

Config::Config(QObject* p) : QObject(p) {}

QString Config::ensureUserConfigPath() const {
    QString dir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    if (dir.isEmpty()) {
        // 退而求其次：當前目錄
        dir = QDir::currentPath() + "/config";
    }
    QDir().mkpath(dir);
    return QDir(dir).filePath(kUserFile);
}

QString Config::userConfigPath() const {
    return ensureUserConfigPath();
}

bool Config::load() {
    // QJsonObject tmp;
    // // 先讀使用者檔
    // if (readJsonFromFile(ensureUserConfigPath(), tmp)) {
    //     QMutexLocker lk(&mtx_);
    //     obj_ = std::move(tmp);
    //     return true;
    // }
    // // 沒有就讀資源預設
    // if (!readJsonFromResource(":/config/default.json", tmp)) {
    //     return false;
    // }
    // {
    //     QMutexLocker lk(&mtx_);
    //     obj_ = std::move(tmp);
    // }
    // // 落地一份到使用者檔
    // return save();

    QJsonObject user;
    if (readJsonFromFile(ensureUserConfigPath(), user)) {
        QJsonObject res;
        if (readJsonFromResource(":/config/default.json", res)) {
            // 覆蓋或做「資源為主、使用者覆寫同名鍵」的合併
            for (auto it = res.begin(); it != res.end(); ++it)
                if (!user.contains(it.key())) user[it.key()] = it.value();
            { QMutexLocker lk(&mtx_); obj_ = user; }
            save();
            return true;
        }
        { QMutexLocker lk(&mtx_); obj_ = user; }
        return true;
    }
    // 沒有使用者檔 → 讀資源並落地
    QJsonObject res;
    if (!readJsonFromResource(":/config/default.json", res)) return false;
    { QMutexLocker lk(&mtx_); obj_ = res; }
    return save();
}

bool Config::loadFromFile(const QString& path) {
    QFile f(path);
    if (!f.exists()) return false;
    if (!f.open(QIODevice::ReadOnly)) return false;
    auto doc = QJsonDocument::fromJson(f.readAll());
    if (!doc.isObject()) return false;
    QMutexLocker lk(&mtx_);
    obj_ = doc.object();
    return true;
}

bool Config::loadFromResource(const QString& resPath) {
    QFile f(resPath);
    if (!f.open(QIODevice::ReadOnly)) return false;
    auto doc = QJsonDocument::fromJson(f.readAll());
    if (!doc.isObject()) return false;
    QMutexLocker lk(&mtx_);
    obj_ = doc.object();
    return true;
}

bool Config::readJsonFromResource(const QString& resPath, QJsonObject& out) {
    QFile f(resPath);
    if (!f.open(QIODevice::ReadOnly)) return false;
    QJsonParseError err{};
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) return false;
    out = doc.object();
    return true;
}

bool Config::readJsonFromFile(const QString& path, QJsonObject& out) {
    QFile f(path);
    if (!f.exists()) return false;
    if (!f.open(QIODevice::ReadOnly)) return false;
    QJsonParseError err{};
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) return false;
    out = doc.object();
    return true;
}

bool Config::save() {
    QMutexLocker lk(&mtx_);
    QJsonDocument doc(obj_);
    const QString path = ensureUserConfigPath();
    QSaveFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    if (f.write(doc.toJson(QJsonDocument::Indented)) < 0) return false;
    return f.commit();
}

// === 欄位讀寫（含預設值） ===
int Config::previewLimitBytes() const {
    QMutexLocker lk(&mtx_);
    const auto v = obj_.value("previewLimitBytes");
    return v.isDouble() ? int(v.toDouble()) : 1048576;
}
void Config::setPreviewLimitBytes(int v) {
    QMutexLocker lk(&mtx_);
    obj_["previewLimitBytes"] = v;
}

int Config::chunkAppendSize() const {
    QMutexLocker lk(&mtx_);
    const auto v = obj_.value("chunkAppendSize");
    return v.isDouble() ? int(v.toDouble()) : 131072;
}
void Config::setChunkAppendSize(int v) {
    QMutexLocker lk(&mtx_);
    obj_["chunkAppendSize"] = v;
}

ThemeMode Config::themeMode() const {
    QMutexLocker lk(&mtx_);
    const auto ui = obj_.value("ui").toObject();
    const QString s = ui.value("theme").toString("system").trimmed().toLower();
    if (s == "dark")  return ThemeMode::Dark;
    if (s == "light") return ThemeMode::Light;
    return ThemeMode::System;
}
void Config::setThemeMode(ThemeMode v) {
    QMutexLocker lk(&mtx_);
    switch (v) {
    case ThemeMode::Dark:
        obj_["ui/theme"] = "dark";
        break;
    case ThemeMode::Light:
        obj_["ui/theme"] = "light";
        break;
    case ThemeMode::System:
        obj_["ui/theme"] = "system";
        break;
    default:
        break;
    }
}
