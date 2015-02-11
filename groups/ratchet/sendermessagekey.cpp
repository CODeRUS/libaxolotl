#include "sendermessagekey.h"
#include "../../kdf/hkdf.h"
#include "../../util/byteutil.h"

SenderMessageKey::SenderMessageKey()
{

}

SenderMessageKey::SenderMessageKey(int iteration, const QByteArray &seed)
{
    QByteArray derivative   = HKDF(3).deriveSecrets(seed, QByteArray("WhisperGroup"), 48);
    QList<QByteArray> parts = ByteUtil::split(derivative, 16, 32);

    this->iteration = iteration;
    this->seed      = seed;
    this->iv        = parts[0];
    this->cipherKey = parts[1];
}

int SenderMessageKey::getIteration() const
{
    return iteration;
}

QByteArray SenderMessageKey::getIv() const
{
    return iv;
}

QByteArray SenderMessageKey::getCipherKey() const
{
    return cipherKey;
}

QByteArray SenderMessageKey::getSeed() const
{
    return seed;
}
