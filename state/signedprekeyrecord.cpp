#include "signedprekeyrecord.h"
#include "../ecc/curve.h"

SignedPreKeyRecord::SignedPreKeyRecord(qulonglong id, long timestamp, const ECKeyPair &keyPair, const QByteArray &signature)
{
    QByteArray bytePublic = keyPair.getPublicKey().serialize();
    QByteArray bytePrivate = keyPair.getPrivateKey().serialize();

    structure.set_id(id);
    structure.set_publickey(bytePublic.constData(), bytePublic.size());
    structure.set_privatekey(bytePrivate.constData(), bytePrivate.size());
    structure.set_signature(signature.constData(), signature.size());
    structure.set_timestamp(timestamp);
}

SignedPreKeyRecord::SignedPreKeyRecord(const QByteArray &serialized)
{
    structure.ParsePartialFromArray(serialized.constData(), serialized.size());
}

qulonglong SignedPreKeyRecord::getId() const
{
    return structure.id();
}

long SignedPreKeyRecord::getTimestamp() const
{
    return structure.timestamp();
}

ECKeyPair SignedPreKeyRecord::getKeyPair() const
{
    ::std::string publickey = structure.publickey();
    QByteArray publicPoint(publickey.data(), publickey.length());
    DjbECPublicKey publicKey = Curve::decodePoint(publicPoint, 0);

    ::std::string privatekey = structure.privatekey();
    QByteArray privatePoint(privatekey.data(), privatekey.length());
    DjbECPrivateKey privateKey = Curve::decodePrivatePoint(privatePoint);

    return ECKeyPair(publicKey, privateKey);
}

QByteArray SignedPreKeyRecord::getSignature() const
{
    ::std::string signature = structure.signature();
    return QByteArray(signature.data(), signature.length());
}

QByteArray SignedPreKeyRecord::serialize() const
{
    ::std::string serialized = structure.SerializeAsString();
    return QByteArray(serialized.data(), serialized.length());
}
