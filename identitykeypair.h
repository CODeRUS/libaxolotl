#ifndef IDENTITYKEYPAIR_H
#define IDENTITYKEYPAIR_H

#include "ecc/djbec.h"
#include "identitykey.h"

class IdentityKeyPair
{
public:
    IdentityKeyPair();
    IdentityKeyPair(const IdentityKey &publicKey, const DjbECPrivateKey &privateKey);
    IdentityKeyPair(const QByteArray &serialized);

    IdentityKey getPublicKey() const;
    DjbECPrivateKey getPrivateKey() const;

private:
    IdentityKey publicKey;
    DjbECPrivateKey privateKey;

};

#endif // IDENTITYKEYPAIR_H
