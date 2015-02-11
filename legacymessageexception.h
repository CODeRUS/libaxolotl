#ifndef LEGACYMESSAGEEXCEPTION_H
#define LEGACYMESSAGEEXCEPTION_H

#include "whisperexception.h"

class LegacyMessageException : public WhisperException
{
public:
    LegacyMessageException(const QString &error) : WhisperException("LegacyMessageException", error) {}
};

#endif // LEGACYMESSAGEEXCEPTION_H
