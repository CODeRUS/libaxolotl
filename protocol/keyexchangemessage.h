#ifndef KEYEXCHANGEMESSAGE_H
#define KEYEXCHANGEMESSAGE_H

#include <QByteArray>
#include "../ecc/djbec.h"
#include "../identitykey.h"

class KeyExchangeMessage
{
public:
    KeyExchangeMessage();
    KeyExchangeMessage(int messageVersion, int sequence, int flags,
                       const DjbECPublicKey &baseKey, const QByteArray &baseKeySignature,
                       const DjbECPublicKey &ratchetKey, const IdentityKey &identityKey);
    KeyExchangeMessage(const QByteArray &serialized);

    static const int INITIATE_FLAG              = 0x01;
    static const int RESPONSE_FLAG              = 0x02;
    static const int SIMULTAENOUS_INITIATE_FLAG = 0x04;

    int getVersion() const;
    DjbECPublicKey getBaseKey() const;
    QByteArray getBaseKeySignature() const;
    DjbECPublicKey getRatchetKey() const;
    IdentityKey getIdentityKey() const;
    bool hasIdentityKey() const;
    int getMaxVersion() const;
    bool isResponse() const;
    bool isInitiate() const;
    bool isResponseForSimultaneousInitiate() const;
    int getFlags() const;
    int getSequence() const;
    QByteArray serialize() const;

private:
    int         version;
    int         supportedVersion;
    int         sequence;
    int         flags;

    DjbECPublicKey baseKey;
    QByteArray  baseKeySignature;
    DjbECPublicKey ratchetKey;
    IdentityKey identityKey;
    QByteArray  serialized;
};

#endif // KEYEXCHANGEMESSAGE_H
