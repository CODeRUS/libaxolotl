#ifndef SIGNEDPREKEYRECORD_H
#define SIGNEDPREKEYRECORD_H

#include "LocalStorageProtocol.pb.h"
#include "../ecc/eckeypair.h"

class SignedPreKeyRecord
{
public:
    SignedPreKeyRecord(qulonglong id, long timestamp, const ECKeyPair &keyPair, const QByteArray &signature);
    SignedPreKeyRecord(const QByteArray &serialized);

    qulonglong getId() const;
    long getTimestamp() const;
    ECKeyPair getKeyPair() const;
    QByteArray getSignature() const;
    QByteArray serialize() const;

private:
    textsecure::SignedPreKeyRecordStructure structure;
};

#endif // SIGNEDPREKEYRECORD_H
