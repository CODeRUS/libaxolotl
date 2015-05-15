#include "prekeyrecord.h"

PreKeyRecord::PreKeyRecord(qulonglong id, const ECKeyPair &keyPair)
{
    QByteArray bytePublic = keyPair.getPublicKey().serialize();
    QByteArray bytePrivate = keyPair.getPrivateKey().serialize();

    structure.set_id(id);
    structure.set_publickey(bytePublic.constData(), bytePublic.size());
    structure.set_privatekey(bytePrivate.constData(), bytePrivate.size());
}

PreKeyRecord::PreKeyRecord(const QByteArray &serialized)
{
    structure.ParsePartialFromArray(serialized.constData(), serialized.size());
}

qulonglong PreKeyRecord::getId() const
{
    return structure.id();
}

ECKeyPair PreKeyRecord::getKeyPair() const
{
    ::std::string publickey = structure.publickey();
    DjbECPublicKey publicKey = Curve::decodePoint(QByteArray(publickey.data(), publickey.length()), 0);
    ::std::string privatekey = structure.privatekey();
    DjbECPrivateKey privateKey = Curve::decodePrivatePoint(QByteArray(privatekey.data(), privatekey.length()));
    return ECKeyPair(publicKey, privateKey);
}

QByteArray PreKeyRecord::serialize() const
{
    std::string str = structure.SerializeAsString();
    QByteArray bytes(str.data(), str.size());
    return bytes;
}
