#include "CryptoWorker.h"
#include <QtCore>


CryptoWorker::CryptoWorker(QObject* parent) : QObject(parent) {}


void CryptoWorker::runAisio(const QStringList& args) {
	// 預設在 PATH 找到 aisio；或填入絕對路徑
	const QString program = "aisio";
	startProcess(program, args);
}


void CryptoWorker::runAisioJson(const QString& apiName, const QString& jsonPayload) {
	const QString program = "aisio";
	QStringList args{ apiName, "--json" };
	startProcess(program, args, jsonPayload.toUtf8());
}


void CryptoWorker::startProcess(const QString& program, const QStringList& arguments, const QByteArray& stdinData) {
	auto* p = new QProcess(this);
	p->setProgram(program);
	p->setArguments(arguments);

	// 設定 UTF-8 環境變數，避免部分系統預設非 UTF-8 編碼導致亂碼
	QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
	env.insert("LANG", "C.UTF-8");
	env.insert("LC_ALL", "C.UTF-8");
	p->setProcessEnvironment(env);

	// 合併管線方便取得錯誤
	p->setProcessChannelMode(QProcess::SeparateChannels);


	connect(p, &QProcess::started, this, [this]() { emit started(); });

	connect(p, &QProcess::finished, this, [this, p](int exitCode, QProcess::ExitStatus) {
#ifdef Q_OS_WIN
		const QString out = QString::fromLocal8Bit(p->readAllStandardOutput());
		const QString err = QString::fromLocal8Bit(p->readAllStandardError());
#else
		const QString out = QString::fromUtf8(p->readAllStandardOutput());
		const QString err = QString::fromUtf8(p->readAllStandardError());
#endif
		emit finished(out, err, exitCode);
		p->deleteLater();
		});


	p->start();


	if (!stdinData.isEmpty()) {
		p->write(stdinData);
		p->closeWriteChannel();
	}
}