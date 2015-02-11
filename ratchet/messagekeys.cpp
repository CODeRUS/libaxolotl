#include "messagekeys.h"

MessageKeys::MessageKeys()
{

}

MessageKeys::MessageKeys(const QByteArray &cipherKey, const QByteArray &macKey, const QByteArray &iv, uint counter)
{
    this->cipherKey = cipherKey;
    this->macKey = macKey;
    this->iv = iv;
    this->counter = counter;
}

QByteArray MessageKeys::getCipherKey() const
{
    return cipherKey;
}

QByteArray MessageKeys::getMacKey() const
{
    return macKey;
}

QByteArray MessageKeys::getIv() const
{
    return iv;
}

uint MessageKeys::getCounter() const
{
    return counter;
}
