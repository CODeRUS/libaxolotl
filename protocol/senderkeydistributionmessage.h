#ifndef SENDERKEYDISTRIBUTIONMESSAGE_H
#define SENDERKEYDISTRIBUTIONMESSAGE_H

#include "ciphertextmessage.h"
#include "../ecc/djbec.h"

class SenderKeyDistributionMessage : public CiphertextMessage
{
public:
    SenderKeyDistributionMessage(int id, int iteration, const QByteArray &chainKey, const DjbECPublicKey &signatureKey);
    virtual ~SenderKeyDistributionMessage() {}

    QByteArray serialize() const;
    int getType() const;
    int getIteration() const;
    QByteArray getChainKey() const;
    DjbECPublicKey getSignatureKey() const;
    int getId() const;

private:
    int         id;
    int         iteration;
    QByteArray  chainKey;
    DjbECPublicKey signatureKey;
    QByteArray  serialized;
};

#endif // SENDERKEYDISTRIBUTIONMESSAGE_H
