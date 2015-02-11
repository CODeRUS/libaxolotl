#ifndef PREKEYRECORD_H
#define PREKEYRECORD_H

#include <QByteArray>

#include "LocalStorageProtocol.pb.h"
#include "../ecc/curve.h"
#include "../ecc/eckeypair.h"

class PreKeyRecord
{
public:
    PreKeyRecord(qulonglong id, const ECKeyPair &keyPair);
    PreKeyRecord(const QByteArray &serialized);

    qulonglong getId() const;
    ECKeyPair getKeyPair() const;
    QByteArray serialize() const;

private:
    textsecure::PreKeyRecordStructure structure;

};

#endif // PREKEYRECORD_H
