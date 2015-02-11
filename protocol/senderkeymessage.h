#ifndef SENDERKEYMESSAGE_H
#define SENDERKEYMESSAGE_H

#include "ciphertextmessage.h"
#include "../ecc/djbec.h"

class SenderKeyMessage : public CiphertextMessage
{
public:
    SenderKeyMessage(const QByteArray &serialized);
    SenderKeyMessage(ulong keyId, int iteration, const QByteArray &ciphertext, const DjbECPrivateKey &signatureKey);
    virtual ~SenderKeyMessage() {}

    void verifySignature(const DjbECPublicKey &signatureKey);

    ulong getKeyId() const;
    int getIteration() const;
    QByteArray getCipherText() const;
    QByteArray serialize() const;
    int getType() const;

private:
    static const int SIGNATURE_LENGTH = 64;

    QByteArray getSignature(const DjbECPrivateKey &signatureKey, const QByteArray &serialized);

    int         messageVersion;
    ulong       keyId;
    int         iteration;
    QByteArray  ciphertext;
    QByteArray  serialized;
};

#endif // SENDERKEYMESSAGE_H
