#include "djbec.h"
#include "../util/byteutil.h"
#include "curve.h"

DjbECPublicKey::DjbECPublicKey()
{
    this->publicKey.clear();
}

DjbECPublicKey::DjbECPublicKey(const DjbECPublicKey &publicKey)
{
    this->publicKey = publicKey.getPublicKey();
}

DjbECPublicKey::DjbECPublicKey(const QByteArray &publicKey)
{
    this->publicKey = publicKey;
}

QByteArray DjbECPublicKey::serialize() const
{
    if (!publicKey.isEmpty()) {
        QByteArray serialized(1, (char)Curve::DJB_TYPE);
        serialized.append(publicKey);
        return serialized;
    }
    return QByteArray();
}

int DjbECPublicKey::getType() const
{
    return Curve::DJB_TYPE;
}

QByteArray DjbECPublicKey::getPublicKey() const
{
    return publicKey;
}

bool DjbECPublicKey::operator <(const DjbECPublicKey &otherKey)
{
    return publicKey != otherKey.publicKey;
}

bool DjbECPublicKey::operator ==(const DjbECPublicKey &otherKey)
{
    return publicKey == otherKey.publicKey;
}

DjbECPrivateKey::DjbECPrivateKey()
{
    this->privateKey.clear();
}

DjbECPrivateKey::DjbECPrivateKey(const DjbECPrivateKey &privateKey)
{
    this->privateKey = privateKey.getPrivateKey();
}

DjbECPrivateKey::DjbECPrivateKey(const QByteArray &privateKey)
{
    this->privateKey = privateKey;
}

QByteArray DjbECPrivateKey::serialize() const
{
    return privateKey;
}

int DjbECPrivateKey::getType() const
{
    return Curve::DJB_TYPE;
}

QByteArray DjbECPrivateKey::getPrivateKey() const
{
    return privateKey;
}

bool DjbECPrivateKey::operator <(const DjbECPrivateKey &otherKey)
{
    return privateKey != otherKey.privateKey;
}

bool DjbECPrivateKey::operator ==(const DjbECPrivateKey &otherKey)
{
    return privateKey == otherKey.privateKey;
}
