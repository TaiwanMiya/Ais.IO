#ifndef CHUNKED_APPENDER_H
#define CHUNKED_APPENDER_H

#include <QObject>
#include <QTimer>
#include <QWidget>
#include <QPlainTextEdit>
#include <QTextEdit>
#include <QTextCursor>
#include <QTextOption>
#include <QSignalBlocker>
#include <optional>

class ChunkedAppender : public QObject {
    Q_OBJECT
public:
    explicit ChunkedAppender(QWidget* edit, const QByteArray& data,
                             int chunkSize = 128 * 1024, QObject* parent = nullptr)
        : QObject(parent), m_widget(edit), m_data(data), m_chunk(chunkSize)
    {
        m_plain = qobject_cast<QPlainTextEdit*>(edit);
        m_rich  = qobject_cast<QTextEdit*>(edit);
    }

    void start() {
        if (!m_widget || (!m_plain && !m_rich)) { deleteLater(); return; }

        // 共同最佳化（不閃屏、關撤銷）
        if (m_plain) {
            m_plain->setUpdatesEnabled(false);
            m_plain->setUndoRedoEnabled(false);
            m_prevWrap = m_plain->wordWrapMode();
            m_plain->setWordWrapMode(QTextOption::NoWrap);
            m_blocker.emplace(m_plain); // 擋 textChanged
            m_plain->clear();
        } else {
            m_rich->setUpdatesEnabled(false);
            m_rich->setUndoRedoEnabled(false);
            m_prevWrap = m_rich->wordWrapMode();
            m_rich->setWordWrapMode(QTextOption::NoWrap);
            m_blocker.emplace(m_rich);  // 擋 textChanged
            m_rich->clear();
        }

        m_offset = 0;
        QTimer::singleShot(0, this, &ChunkedAppender::pump);
    }

signals:
    void finished();

private slots:
    void pump() {
        const int remain = m_data.size() - m_offset;
        const int take   = qMin(m_chunk, remain);

        if (take > 0) {
            const QString piece = QString::fromLatin1(m_data.constData() + m_offset, take);

            if (m_plain) {
                m_plain->appendPlainText(piece);
            } else {
                // QTextEdit 沒有 appendPlainText()，用游標插入避免多餘換行
                QTextCursor c = m_rich->textCursor();
                c.movePosition(QTextCursor::End);
                c.insertText(piece);
                m_rich->setTextCursor(c);
            }

            m_offset += take;
            QTimer::singleShot(0, this, &ChunkedAppender::pump);
            return;
        }

        // 收尾：恢復設定
        if (m_blocker) m_blocker.reset();
        if (m_plain) {
            m_plain->setWordWrapMode(m_prevWrap);
            m_plain->setUndoRedoEnabled(true);
            m_plain->setUpdatesEnabled(true);
            m_plain->viewport()->update();
        } else {
            m_rich->setWordWrapMode(m_prevWrap);
            m_rich->setUndoRedoEnabled(true);
            m_rich->setUpdatesEnabled(true);
            m_rich->viewport()->update();
        }

        emit finished();
        deleteLater();
    }

private:
    QWidget*        m_widget = nullptr;
    QPlainTextEdit* m_plain  = nullptr;
    QTextEdit*      m_rich   = nullptr;

    QByteArray m_data;
    int        m_chunk  = 128 * 1024;
    int        m_offset = 0;

    std::optional<QSignalBlocker> m_blocker;
    QTextOption::WrapMode m_prevWrap = QTextOption::WrapAtWordBoundaryOrAnywhere;
};

#endif // CHUNKED_APPENDER_H
