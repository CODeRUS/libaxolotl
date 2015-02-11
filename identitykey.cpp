#include "identitykey.h"
#include "ecc/curve.h"

IdentityKey::IdentityKey()
{
}

IdentityKey::IdentityKey(const DjbECPublicKey &publicKey, int offset)
{
    if (offset == 0) {
        this->publicKey = publicKey;
    }
    else {
        this->publicKey = Curve::decodePoint(publicKey.serialize(), offset);
    }
}

IdentityKey::IdentityKey(const QByteArray &publicKey, int offset)
{
    this->publicKey = Curve::decodePoint(publicKey, offset);
}

DjbECPublicKey IdentityKey::getPublicKey() const
{
    return publicKey;
}

QByteArray IdentityKey::serialize() const
{
    return publicKey.serialize();
}

QByteArray IdentityKey::getFingerprint() const
{
    return publicKey.serialize().toHex();
}

QByteArray IdentityKey::hashCode() const
{
    return publicKey.serialize().mid(0, 4); // TODO
}

bool IdentityKey::operator ==(const IdentityKey &otherKey)
{
    return publicKey.serialize() == otherKey.getPublicKey().serialize();
}
