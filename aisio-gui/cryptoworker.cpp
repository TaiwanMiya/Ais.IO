#include "cryptoworker.h"
#include <QProcess>
#include <QProcessEnvironment>

CryptoWorker::CryptoWorker(QObject* parent) : QObject(parent) {}

void CryptoWorker::runAisio(const QStringList& args) {
    startProcess("aisio", args);
}

void CryptoWorker::runAisioJson(const QString& apiName, const QByteArray& jsonUtf8) {
    QStringList args{ apiName, "--json" };
    startProcess("aisio", args, jsonUtf8);
}

void CryptoWorker::startProcess(const QString& program, const QStringList& args, const QByteArray& stdinData) {
    auto* p = new QProcess(this);
    p->setProgram(program);
    p->setArguments(args);
    p->setProcessChannelMode(QProcess::SeparateChannels);

    // 盡量要求 UTF-8（部分程式會忽略，但加總比不加好）
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert("LANG",   "C.UTF-8");
    env.insert("LC_ALL", "C.UTF-8");
    p->setProcessEnvironment(env);

    connect(p, &QProcess::started, this, [this]() { emit started(); });

    connect(p, &QProcess::finished, this, [this, p](int exitCode, QProcess::ExitStatus) {
        const QByteArray so = p->readAllStandardOutput();
        const QByteArray se = p->readAllStandardError();
        const QString out = QString::fromUtf8(so);
        const QString err = QString::fromUtf8(se);
        emit finished(out, err, exitCode);
        p->deleteLater();
    });

    p->start();
    if (!stdinData.isEmpty()) {
        p->write(stdinData);     // 我們保證是 UTF-8
        p->closeWriteChannel();
    }
}
