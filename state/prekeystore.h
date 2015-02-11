#ifndef PREKEYSTORE_H
#define PREKEYSTORE_H

#include "prekeyrecord.h"

class PreKeyStore {
public:
    virtual PreKeyRecord loadPreKey(qulonglong preKeyId) = 0;
    virtual void         storePreKey(qulonglong preKeyId, const PreKeyRecord &record) = 0;
    virtual bool         containsPreKey(qulonglong preKeyId) = 0;
    virtual void         removePreKey(qulonglong preKeyId) = 0;
    virtual int          countPreKeys() = 0;
};

#endif // PREKEYSTORE_H
