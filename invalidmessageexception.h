#ifndef INVALIDMESSAGEEXCEPTION_H
#define INVALIDMESSAGEEXCEPTION_H

#include "whisperexception.h"

class InvalidMessageException : public WhisperException
{
public:
    InvalidMessageException(const QString &error) : WhisperException("InvalidMessageException", error) {}
    InvalidMessageException(const QString &error, const QList<WhisperException> &exceptions) : WhisperException("InvalidMessageException", error) {
        foreach (const WhisperException &exception, exceptions) {
            _error.append(" ");
            _error.append(exception.errorMessage());
        }
    }
};

#endif // INVALIDMESSAGEEXCEPTION_H
