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
    // QMutexLocker lk(&mtx_);
    // // 先嘗試讀使用者檔
    // if (loadFromFile(ensureUserConfigPath()))
    //     return true;
    // // 沒有 → 讀資源預設，並寫一份到使用者目錄
    // if (!loadFromResource(kResDefault))
    //     return false;
    // lk.unlock(); // 避免死鎖：save 也會鎖
    // return save();

    QJsonObject tmp;
    // 先讀使用者檔
    if (readJsonFromFile(ensureUserConfigPath(), tmp)) {
        QMutexLocker lk(&mtx_);
        obj_ = std::move(tmp);
        return true;
    }
    // 沒有就讀資源預設
    if (!readJsonFromResource(":/config/default.json", tmp)) {
        return false;
    }
    {
        QMutexLocker lk(&mtx_);
        obj_ = std::move(tmp);
    }
    // 落地一份到使用者檔
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
    qDebug() << "[Config] previewLimitBytes =" << v << v.toDouble();
    return v.isDouble() ? int(v.toDouble()) : 1048576; // 1 MiB 預設
}
void Config::setPreviewLimitBytes(int v) {
    QMutexLocker lk(&mtx_);
    obj_["previewLimitBytes"] = v;
}

int Config::chunkAppendSize() const {
    QMutexLocker lk(&mtx_);
    const auto v = obj_.value("chunkAppendSize");
    return v.isDouble() ? int(v.toDouble()) : 131072;  // 128 KiB 預設
}
void Config::setChunkAppendSize(int v) {
    QMutexLocker lk(&mtx_);
    obj_["chunkAppendSize"] = v;
}
