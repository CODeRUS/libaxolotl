#ifndef STALEKEYEXCHANGEEXCEPTION_H
#define STALEKEYEXCHANGEEXCEPTION_H

#include "whisperexception.h"

class StaleKeyExchangeException : public WhisperException
{
public:
    StaleKeyExchangeException(const QString &error) : WhisperException("StaleKeyExchangeException", error) {}
};

#endif // STALEKEYEXCHANGEEXCEPTION_H
