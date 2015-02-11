#include "prekeybundle.h"

PreKeyBundle::PreKeyBundle(qulonglong registrationId, int deviceId, qulonglong preKeyId, const DjbECPublicKey &preKeyPublic, qulonglong signedPreKeyId, const DjbECPublicKey &signedPreKeyPublic, const QByteArray &signedPreKeySignature, const IdentityKey &identityKey)
{
    this->registrationId        = registrationId;
    this->deviceId              = deviceId;
    this->preKeyId              = preKeyId;
    this->preKeyPublic          = preKeyPublic;
    this->signedPreKeyId        = signedPreKeyId;
    this->signedPreKeyPublic    = signedPreKeyPublic;
    this->signedPreKeySignature = signedPreKeySignature;
    this->identityKey           = identityKey;
}

int PreKeyBundle::getDeviceId() const
{
    return deviceId;
}

qulonglong PreKeyBundle::getPreKeyId() const
{
    return preKeyId;
}

DjbECPublicKey PreKeyBundle::getPreKey() const
{
    return preKeyPublic;
}

qulonglong PreKeyBundle::getSignedPreKeyId() const
{
    return signedPreKeyId;
}

DjbECPublicKey PreKeyBundle::getSignedPreKey() const
{
    return signedPreKeyPublic;
}

QByteArray PreKeyBundle::getSignedPreKeySignature() const
{
    return signedPreKeySignature;
}

IdentityKey PreKeyBundle::getIdentityKey() const
{
    return identityKey;
}

qulonglong PreKeyBundle::getRegistrationId() const
{
    return registrationId;
}
