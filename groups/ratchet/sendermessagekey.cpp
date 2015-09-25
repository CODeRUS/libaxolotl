#include "sendermessagekey.h"
#include "kdf/hkdf.h"

SenderMessageKey::SenderMessageKey()
{

}

SenderMessageKey::SenderMessageKey(int iteration, const QByteArray &seed)
{
    QByteArray derivative   = HKDF(3).deriveSecrets(seed, QByteArray("WhisperGroup"), 48);

    this->iteration = iteration;
    this->seed      = seed;
    this->iv        = derivative.left(16);
    this->cipherKey = derivative.mid(16, 32);
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
