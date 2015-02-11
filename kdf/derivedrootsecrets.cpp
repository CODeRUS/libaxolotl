#include "derivedrootsecrets.h"
#include "../util/byteutil.h"

const int DerivedRootSecrets::SIZE = 64;

DerivedRootSecrets::DerivedRootSecrets(const QByteArray &okm)
{
    QList<QByteArray> keys = ByteUtil::split(okm, 32, 32);
    rootKey = keys[0];
    chainKey = keys[1];
}

QByteArray DerivedRootSecrets::getRootKey() const
{
    return rootKey;
}

QByteArray DerivedRootSecrets::getChainKey() const
{
    return chainKey;
}
