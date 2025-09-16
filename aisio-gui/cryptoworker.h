#pragma once
#include <QObject>
#include <QStringList>

class QProcess;

class CryptoWorker : public QObject {
    Q_OBJECT
public:
    explicit CryptoWorker(QObject* parent = nullptr);

    // 直接以參數呼叫 aisio <ApiName> ...
    void runAisio(const QStringList& args);

    // 以 JSON 請求呼叫：aisio <ApiName> --json  (payload 走 stdin, UTF-8)
    void runAisioJson(const QString& apiName, const QByteArray& jsonUtf8);

signals:
    void started();
    void finished(const QString& output, const QString& err, int exitCode);

private:
    void startProcess(const QString& program, const QStringList& args, const QByteArray& stdinData = {});
};
