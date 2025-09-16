#pragma once
#include <QObject>
#include <QStringList>


class QProcess;


class CryptoWorker : public QObject {
	Q_OBJECT
public:
	explicit CryptoWorker(QObject* parent = nullptr);


	// 直接以 aisio 子程序 + 參數呼叫
	void runAisio(const QStringList& args);


	// 以 aisio 接收 API 名稱 + JSON 的方式呼叫（stdout 回傳）
	void runAisioJson(const QString& apiName, const QString& jsonPayload);


signals:
	void started();
	void finished(const QString& output, const QString& err, int exitCode);


private:
	void startProcess(const QString& program, const QStringList& arguments, const QByteArray& stdinData = {});
};