#include "derivedmessagesecrets.h"
#include "../util/byteutil.h"

#include <QList>

const int DerivedMessageSecrets::SIZE = 80;
const int DerivedMessageSecrets::CIPHER_KEY_LENGTH = 32;
const int DerivedMessageSecrets::MAC_KEY_LENGTH = 32;
const int DerivedMessageSecrets::IV_LENGTH = 16;

DerivedMessageSecrets::DerivedMessageSecrets(const QByteArray &okm)
{
    QList<QByteArray> keys = ByteUtil::split(okm,
                                             DerivedMessageSecrets::CIPHER_KEY_LENGTH,
                                             DerivedMessageSecrets::MAC_KEY_LENGTH,
                                             DerivedMessageSecrets::IV_LENGTH);
    cipherKey = keys[0]; //AES
    macKey = keys[1]; //sha256
    iv = keys[2];
}

QByteArray DerivedMessageSecrets::getCipherKey() const
{
    return cipherKey;
}

QByteArray DerivedMessageSecrets::getMacKey() const
{
    return macKey;
}

QByteArray DerivedMessageSecrets::getIv() const
{
    return iv;
}
