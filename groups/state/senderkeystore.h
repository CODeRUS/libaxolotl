#ifndef SENDERKEYSTORE_H
#define SENDERKEYSTORE_H

#include "senderkeyrecord.h"
#include <QByteArray>

class SenderKeyStore
{
public:
    virtual void storeSenderKey(const QByteArray &senderKeyId, SenderKeyRecord *record) = 0;
    virtual SenderKeyRecord loadSenderKey(const QByteArray &senderKeyId) const = 0;
};

#endif // SENDERKEYSTORE_H
