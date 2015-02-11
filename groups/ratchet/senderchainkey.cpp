#include "senderchainkey.h"
#include <QMessageAuthenticationCode>

const QByteArray SenderChainKey::MESSAGE_KEY_SEED = QByteArray("\0x01");
const QByteArray SenderChainKey::CHAIN_KEY_SEED = QByteArray("\0x02");

SenderChainKey::SenderChainKey(int iteration, const QByteArray &chainKey)
{
    this->iteration = iteration;
    this->chainKey = chainKey;
}

int SenderChainKey::getIteration() const
{
    return iteration;
}

SenderMessageKey SenderChainKey::getSenderMessageKey() const
{
    return SenderMessageKey(iteration, getDerivative(MESSAGE_KEY_SEED, chainKey));
}

SenderChainKey SenderChainKey::getNext() const
{
    return SenderChainKey(iteration + 1, getDerivative(CHAIN_KEY_SEED, chainKey));
}

QByteArray SenderChainKey::getSeed() const
{
    return chainKey;
}

QByteArray SenderChainKey::getDerivative(const QByteArray &seed, const QByteArray &key) const
{
    return QMessageAuthenticationCode::hash(seed, key, QCryptographicHash::Sha256);
}
