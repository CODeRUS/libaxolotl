#ifndef WHISPEREXCEPTION_H
#define WHISPEREXCEPTION_H

#include <QException>
#include <QString>

class WhisperException : public QException
{
public:
    WhisperException(const QString &type, const QString &error = QString("Unknown error")) throw() {
        _error = error;
        _type = type;
    }
    QString errorType() const {
        return _type;
    }
    QString errorMessage() const {
        return _error;
    }
    WhisperException(const WhisperException &source) {
        _error = source.errorMessage();
    }
    virtual ~WhisperException() throw() {}

    void raise() const { throw *this; }
    WhisperException *clone() const { return new WhisperException(*this); }

protected:
    QString _error;
    QString _type;
};

#endif // WHISPEREXCEPTION_H
