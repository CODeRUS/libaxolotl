#ifndef PREKEYBUNDLE_H
#define PREKEYBUNDLE_H

#include "../ecc/djbec.h"
#include "../identitykey.h"

class PreKeyBundle
{
public:
    PreKeyBundle(qulonglong registrationId, int deviceId, qulonglong preKeyId, const DjbECPublicKey &preKeyPublic, qulonglong signedPreKeyId, const DjbECPublicKey &signedPreKeyPublic, const QByteArray &signedPreKeySignature, const IdentityKey &identityKey);

    int getDeviceId() const;
    qulonglong getPreKeyId() const;
    DjbECPublicKey getPreKey() const;
    qulonglong getSignedPreKeyId() const;
    DjbECPublicKey getSignedPreKey() const;
    QByteArray getSignedPreKeySignature() const;
    IdentityKey getIdentityKey() const;
    qulonglong getRegistrationId() const;

private:
    qulonglong registrationId;
    int deviceId;
    qulonglong preKeyId;
    DjbECPublicKey preKeyPublic;
    qulonglong signedPreKeyId;
    DjbECPublicKey signedPreKeyPublic;
    QByteArray signedPreKeySignature;
    IdentityKey identityKey;

};

#endif // PREKEYBUNDLE_H
