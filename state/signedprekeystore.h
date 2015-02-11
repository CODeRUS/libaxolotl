#ifndef SIGNEDPREKEYSTORE_H
#define SIGNEDPREKEYSTORE_H

#include "signedprekeyrecord.h"

class SignedPreKeyStore
{
public:
    virtual SignedPreKeyRecord loadSignedPreKey(qulonglong signedPreKeyId) = 0;
    virtual QList<SignedPreKeyRecord> loadSignedPreKeys() = 0;
    virtual void storeSignedPreKey(qulonglong signedPreKeyId, const SignedPreKeyRecord &record) = 0;
    virtual bool containsSignedPreKey(qulonglong signedPreKeyId) = 0;
    virtual void removeSignedPreKey(qulonglong signedPreKeyId) = 0;
};

#endif // SIGNEDPREKEYSTORE_H
