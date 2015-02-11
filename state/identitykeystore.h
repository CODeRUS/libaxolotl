#ifndef IDENTITYKEYSTORE_H
#define IDENTITYKEYSTORE_H

#include "../identitykeypair.h"

class IdentityKeyStore {
public:
    virtual IdentityKeyPair getIdentityKeyPair() = 0;
    virtual uint            getLocalRegistrationId() = 0;
    virtual void            storeLocalData(qulonglong registrationId, const IdentityKeyPair identityKeyPair) = 0;
    virtual void            saveIdentity(qulonglong recipientId, const IdentityKey &identityKey) = 0;
    virtual bool            isTrustedIdentity(qulonglong recipientId, const IdentityKey &identityKey) = 0;
    virtual void            removeIdentity(qulonglong recipientId) = 0;
};

#endif // IDENTITYKEYSTORE_H
