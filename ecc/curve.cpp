#include "curve.h"

#include "../invalidkeyexception.h"

#include "../libcurve25519/curve.h"

#include <openssl/rand.h>

const int Curve::DJB_TYPE = 5;

ECKeyPair Curve::generateKeyPair()
{
    RAND_poll();

    unsigned char buff1[32];
    memset(buff1, 0, 32);
    RAND_bytes(buff1, 32);

    QByteArray privateKey = QByteArray::fromRawData((const char*)buff1, 32);
    Curve25519::generatePrivateKey(privateKey.data());
    QByteArray publicKey(32, '\0');
    Curve25519::generatePublicKey(privateKey.constData(), publicKey.data());
    return ECKeyPair(DjbECPublicKey(publicKey), DjbECPrivateKey(privateKey));
}

DjbECPublicKey Curve::decodePoint(const QByteArray &privatePoint, int offset)
{
    quint8 type = privatePoint[0];

    if (type == Curve::DJB_TYPE) {
        type = privatePoint[offset] & 0xFF;
        if (type != Curve::DJB_TYPE) {
            throw InvalidKeyException(QString("Unknown key type: %1 ").arg(type));
        }
        QByteArray keyBytes = privatePoint.mid(offset+1, 32);
        DjbECPublicKey pubkey(keyBytes);
        return pubkey;
    }
    else {
        throw InvalidKeyException(QString("Unknown key type: %1").arg(type));
    }
}

DjbECPrivateKey Curve::decodePrivatePoint(const QByteArray &privatePoint)
{
    return DjbECPrivateKey(privatePoint);
}

QByteArray Curve::calculateAgreement(const DjbECPublicKey &publicKey, const DjbECPrivateKey &privateKey)
{
    if (publicKey.getType() != privateKey.getType()) {
        throw InvalidKeyException("Public and private keys must be of the same type!");
    }

    if (publicKey.getType() == DJB_TYPE) {
        QByteArray sharedKey(32, '\0');
        Curve25519::calculateAgreement(privateKey.getPrivateKey().constData(),
                                       publicKey.getPublicKey().constData(),
                                       sharedKey.data());
        return sharedKey;
    } else {
        throw InvalidKeyException("Unknown type: " + publicKey.getType());
    }
}

bool Curve::verifySignature(const DjbECPublicKey &signingKey, const QByteArray &message, const QByteArray &signature)
{
    if (signingKey.getType() == DJB_TYPE) {
        return Curve25519::verifySignature((const unsigned char*)signingKey.getPublicKey().constData(),
                                           (const unsigned char*)message.constData(),
                                           message.size(),
                                           (const unsigned char*)signature.constData());
    } else {
        throw InvalidKeyException(QString("Unknown type: %1").arg(signingKey.getType()));
    }
}

QByteArray Curve::calculateSignature(const DjbECPrivateKey &signingKey, const QByteArray &message)
{
    if (signingKey.getType() == DJB_TYPE) {
        RAND_poll();

        unsigned char buff1[64];
        memset(buff1, 0, 64);
        RAND_bytes(buff1, 64);

        QByteArray random64 = QByteArray::fromRawData((const char*)buff1, 64);
        QByteArray signature(64, '\0');
        Curve25519::calculateSignature((const unsigned char*)signingKey.getPrivateKey().constData(),
                                       (const unsigned char*)message.constData(),
                                       message.size(),
                                       (const unsigned char*)random64.constData(),
                                       (unsigned char*)signature.data());
        return signature;
    } else {
        throw InvalidKeyException("Unknown type: " + signingKey.getType());
    }
}
