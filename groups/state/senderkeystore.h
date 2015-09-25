#ifndef SENDERKEYSTORE_H
#define SENDERKEYSTORE_H

#include "senderkeyrecord.h"
#include "groups/senderkeyname.h"
#include <QByteArray>

class SenderKeyStore
{
public:
    virtual void storeSenderKey(const SenderKeyName &senderKeyName, const SenderKeyRecord &record) = 0;
    virtual SenderKeyRecord loadSenderKey(const SenderKeyName &senderKeyName) const = 0;
};

#endif // SENDERKEYSTORE_H
