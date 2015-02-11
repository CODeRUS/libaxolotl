#ifndef PREKEYWHISPERMESSAGE_H
#define PREKEYWHISPERMESSAGE_H

#include <QSharedPointer>

#include "ciphertextmessage.h"
#include "../ecc/djbec.h"
#include "../identitykey.h"
#include "whispermessage.h"

class PreKeyWhisperMessage : public CiphertextMessage
{
public:
    PreKeyWhisperMessage(const QByteArray &serialized);
    PreKeyWhisperMessage(int messageVersion, ulong registrationId, ulong preKeyId,
                         ulong signedPreKeyId, const DjbECPublicKey &baseKey, const IdentityKey &identityKey,
                         QSharedPointer<WhisperMessage> message);
    virtual ~PreKeyWhisperMessage() {}

    int getMessageVersion() const;
    IdentityKey getIdentityKey() const;
    ulong getRegistrationId() const;
    ulong getPreKeyId() const;
    ulong getSignedPreKeyId() const;
    DjbECPublicKey getBaseKey() const;
    QSharedPointer<WhisperMessage> getWhisperMessage();
    QByteArray serialize() const;
    int getType() const;

private:
    int               version;
    ulong             registrationId;
    ulong             preKeyId;
    ulong             signedPreKeyId;
    DjbECPublicKey    baseKey;
    IdentityKey       identityKey;
    QSharedPointer<WhisperMessage> message;
    QByteArray        serialized;
};

#endif // PREKEYWHISPERMESSAGE_H
