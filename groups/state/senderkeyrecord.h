#ifndef SENDERKEYRECORD_H
#define SENDERKEYRECORD_H

#include <QList>

#include "senderkeystate.h"
#include "../../ecc/djbec.h"
#include "../../ecc/eckeypair.h"

class SenderKeyRecord
{
public:
    SenderKeyRecord();
    SenderKeyRecord(const QByteArray &serialized);
    SenderKeyState *getSenderKeyState(int keyId = 0);
    void addSenderKeyState(int id, int iteration, const QByteArray &chainKey, const DjbECPublicKey &signatureKey);
    void setSenderKeyState(int id, int iteration, const QByteArray &chainKey, const ECKeyPair &signatureKey);
    QByteArray serialize() const;

private:
    QList<SenderKeyState*> senderKeyStates;
};

#endif // SENDERKEYRECORD_H
