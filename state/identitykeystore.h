#ifndef IDENTITYKEYSTORE_H
#define IDENTITYKEYSTORE_H

#include "../identitykeypair.h"

#include <QString>

class IdentityKeyStore {
public:
    virtual IdentityKeyPair getIdentityKeyPair() = 0;
    virtual uint            getLocalRegistrationId() = 0;
    virtual void            storeLocalData(qulonglong registrationId, const IdentityKeyPair identityKeyPair) = 0;
    virtual void            saveIdentity(const QString &name, const IdentityKey &identityKey) = 0;
    virtual bool            isTrustedIdentity(const QString &name, const IdentityKey &identityKey) = 0;
    virtual void            removeIdentity(const QString &name) = 0;
};

#endif // IDENTITYKEYSTORE_H
