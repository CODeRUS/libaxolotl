#ifndef SENDERKEYRECORD_H
#define SENDERKEYRECORD_H

#include <QList>
#include <QLinkedList>

#include "senderkeystate.h"
#include "ecc/djbec.h"
#include "ecc/eckeypair.h"

class SenderKeyRecord
{
public:
    static const int MAX_STATES = 5;

    SenderKeyRecord();
    SenderKeyRecord(const QByteArray &serialized);
    SenderKeyState *getSenderKeyState();
    SenderKeyState *getSenderKeyState(int keyId);
    void addSenderKeyState(int id, int iteration, const QByteArray &chainKey, const DjbECPublicKey &signatureKey);
    void setSenderKeyState(int id, int iteration, const QByteArray &chainKey, const ECKeyPair &signatureKey);
    QByteArray serialize() const;
    bool isEmpty() const;

private:
    QLinkedList<SenderKeyState*> senderKeyStates;
};

#endif // SENDERKEYRECORD_H
