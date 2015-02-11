#ifndef INVALIDVERSIONEXCEPTION_H
#define INVALIDVERSIONEXCEPTION_H

#include "whisperexception.h"

class InvalidVersionException : public WhisperException
{
public:
    InvalidVersionException(const QString &error) : WhisperException("InvalidVersionException", error) {}
};

#endif // INVALIDVERSIONEXCEPTION_H
