#ifndef CURVE_H
#define CURVE_H

#include "eckeypair.h"
#include "djbec.h"

class Curve
{
public:
    static const int DJB_TYPE;

    static ECKeyPair generateKeyPair();
    static DjbECPublicKey decodePoint(const QByteArray &privatePoint, int offset = 0);
    static DjbECPrivateKey decodePrivatePoint(const QByteArray &privatePoint);
    static QByteArray calculateAgreement(const DjbECPublicKey &publicKey, const DjbECPrivateKey &privateKey);
    static bool verifySignature(const DjbECPublicKey &signingKey, const QByteArray &message, const QByteArray &signature);
    static QByteArray calculateSignature(const DjbECPrivateKey &signingKey, const QByteArray &message);
};

#endif // CURVE_H
