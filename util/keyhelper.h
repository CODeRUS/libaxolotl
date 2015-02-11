#ifndef KEYHELPER_H
#define KEYHELPER_H

#include "../identitykeypair.h"
#include "../state/prekeyrecord.h"
#include "../state/signedprekeyrecord.h"

#include <QList>

class KeyHelper
{
public:
    static quint64 getRandomFFFF();
    static quint64 getRandom7FFFFFFF();
    static quint64 getRandomFFFFFFFF();
    static QByteArray getRandomBytes(int bytes);

    static IdentityKeyPair generateIdentityKeyPair();
    static quint64 generateRegistrationId();
    static QList<PreKeyRecord> generatePreKeys(qulonglong start, uint count);
    static SignedPreKeyRecord generateSignedPreKey(const IdentityKeyPair &identityKeyPair, qulonglong signedPreKeyId);
    static ECKeyPair generateSenderSigningKey();
    static QByteArray generateSenderKey();
    static unsigned long generateSenderKeyId();
};

#endif // KEYHELPER_H
