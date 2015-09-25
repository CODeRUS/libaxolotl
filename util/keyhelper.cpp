#include "keyhelper.h"

#include <openssl/rand.h>

#include <QDateTime>

#include "../ecc/eckeypair.h"
#include "../ecc/curve.h"

quint64 KeyHelper::getRandomFFFF()
{
    unsigned char buff1[2];
    memset(buff1, 0, 2);
    RAND_bytes(buff1, 2);
    quint64 rand1 = ((unsigned int)buff1[1] << 8) + (unsigned int)buff1[0];

    return rand1;
}

quint64 KeyHelper::getRandom7FFFFFFF()
{
    quint64 rand2 = 0;
    for (int i = 0; i < 0x80; i++) {
        unsigned char buff0[3];
        memset(buff0, 0, 3);
        RAND_bytes(buff0, 3);
        rand2 += ((unsigned int)buff0[2] << 16);
        rand2 += ((unsigned int)buff0[1] << 8);
        rand2 += (unsigned int)buff0[0];
    }

    return rand2;
}

quint64 KeyHelper::getRandomFFFFFFFF()
{
    unsigned char buff1[4];
    memset(buff1, 0, 4);
    RAND_bytes(buff1, 4);
    quint64 rand1 = ((unsigned long)buff1[3] << 24) + ((unsigned int)buff1[2] << 16)
                       +  ((unsigned int)buff1[1] << 8)  +  (unsigned int)buff1[0];

    return rand1;
}

QByteArray KeyHelper::getRandomBytes(int bytes)
{
    QByteArray buff1(bytes, '\0');
    RAND_bytes((unsigned char*)buff1.data(), bytes);
    return buff1;
}

IdentityKeyPair KeyHelper::generateIdentityKeyPair()
{
    ECKeyPair keyPair = Curve::generateKeyPair();
    IdentityKey publicKey(keyPair.getPublicKey());
    IdentityKeyPair identityKeyPair(publicKey, keyPair.getPrivateKey());
    return identityKeyPair;
}

quint64 KeyHelper::generateRegistrationId()
{
    return getRandomFFFFFFFF();
}

QList<PreKeyRecord> KeyHelper::generatePreKeys(qulonglong start, uint count)
{
    QList<PreKeyRecord> results;
    for (uint i = 0; i < count; i++) {
        qulonglong preKeyId = ((start + i - 1) % (0xFFFFFE)) + 1;
        results.append(PreKeyRecord(preKeyId, Curve::generateKeyPair()));
    }
    return results;
}

SignedPreKeyRecord KeyHelper::generateSignedPreKey(const IdentityKeyPair &identityKeyPair, qulonglong signedPreKeyId)
{
    ECKeyPair keyPair = Curve::generateKeyPair();
    QByteArray signature = Curve::calculateSignature(identityKeyPair.getPrivateKey(), keyPair.getPublicKey().serialize());
    return SignedPreKeyRecord(signedPreKeyId, QDateTime::currentMSecsSinceEpoch(), keyPair, signature);
}

ECKeyPair KeyHelper::generateSenderSigningKey()
{
    return Curve::generateKeyPair();
}

QByteArray KeyHelper::generateSenderKey()
{
    unsigned char buff1[32];
    memset(buff1, 0, 32);
    RAND_bytes(buff1, 32);

    QByteArray key = QByteArray::fromRawData((const char*)buff1, 32);
    return key;
}

unsigned long KeyHelper::generateSenderKeyId()
{
    return getRandom7FFFFFFF();
}
