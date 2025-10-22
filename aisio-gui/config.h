#pragma once
#include <QObject>
#include <QJsonObject>
#include <QMutex>

enum class ThemeMode {
    System,
    Light,
    Dark
};

class Config : public QObject {
    Q_OBJECT
public:
    static Config& instance();

    bool load();                // 讀使用者檔，不在就讀資源預設
    bool save();                // 存回使用者檔
    QString userConfigPath() const; // 供除錯顯示

    // === 你要的欄位 ===
    int  previewLimitBytes() const;
    void setPreviewLimitBytes(int v);

    int  chunkAppendSize() const;
    void setChunkAppendSize(int v);

    ThemeMode themeMode() const;
    void setThemeMode(ThemeMode v);

private:
    explicit Config(QObject* parent=nullptr);
    bool loadFromFile(const QString& path);
    bool loadFromResource(const QString& resPath);
    QString ensureUserConfigPath() const;  // 建目錄
    static bool readJsonFromResource(const QString& resPath, QJsonObject& out);
    static bool readJsonFromFile(const QString& path, QJsonObject& out);

    mutable QMutex mtx_;
    QJsonObject obj_;
};
