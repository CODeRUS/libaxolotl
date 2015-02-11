#ifndef IDENTITYKEY_H
#define IDENTITYKEY_H

#include "ecc/djbec.h"

class IdentityKey
{
public:
    IdentityKey();
    IdentityKey(const DjbECPublicKey &publicKey, int offset = 0);
    IdentityKey(const QByteArray &publicKey, int offset = 0);

    DjbECPublicKey getPublicKey() const;
    QByteArray serialize() const;
    QByteArray getFingerprint() const;
    QByteArray hashCode() const;
    bool operator ==(const IdentityKey &otherKey);

private:
    DjbECPublicKey publicKey;

};

#endif // IDENTITYKEY_H
