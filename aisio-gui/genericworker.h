#ifndef GENERICWORKER_H
#define GENERICWORKER_H

#pragma once
#include <QObject>
#include <QVariant>
#include <functional>
#include <atomic>

class GenericWorker : public QObject {
    Q_OBJECT
public:
    using ProgressFn = std::function<void(int /*percent*/, qint64 /*done*/, qint64 /*total*/)>;
    using TaskFn     = std::function<QVariant(std::atomic_bool& cancel, const ProgressFn& report)>;

    explicit GenericWorker(TaskFn task, QObject* parent=nullptr)
        : QObject(parent), m_task(std::move(task)) {}

public slots:
    void run() {
        try {
            const auto report = [this](int p, qint64 d, qint64 t) { emit progress(p, d, t); };
            QVariant result = m_task(m_cancel, report);
            if (m_cancel.load()) emit canceled();
            else emit finished(result);
        } catch (const std::exception& e) {
            emit error(QString::fromLocal8Bit(e.what()));
        } catch (const QString& s) {
            emit error(s);
        } catch (...) {
            emit error(tr("Unknown error"));
        }
    }
    void cancel() { m_cancel.store(true); }

signals:
    void progress(int percent, qint64 done, qint64 total);
    void finished(const QVariant& result);
    void canceled();
    void error(const QString& msg);

private:
    TaskFn m_task;
    std::atomic_bool m_cancel{false};
};


#endif // GENERICWORKER_H
