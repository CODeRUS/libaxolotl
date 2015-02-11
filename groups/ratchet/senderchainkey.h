#ifndef SENDERCHAINKEY_H
#define SENDERCHAINKEY_H

#include <QByteArray>
#include "sendermessagekey.h"

class SenderChainKey
{
public:
    SenderChainKey(int iteration, const QByteArray &chainKey);

    int getIteration() const;
    SenderMessageKey getSenderMessageKey() const;
    SenderChainKey getNext() const;
    QByteArray getSeed() const;
    QByteArray getDerivative(const QByteArray &seed, const QByteArray &key) const;

private:
    static const QByteArray MESSAGE_KEY_SEED;
    static const QByteArray CHAIN_KEY_SEED;

    int        iteration;
    QByteArray chainKey;
};

#endif // SENDERCHAINKEY_H
