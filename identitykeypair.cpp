#include "identitykeypair.h"
#include "ecc/curve.h"
#include "state/sessionstate.h"

IdentityKeyPair::IdentityKeyPair()
{

}

IdentityKeyPair::IdentityKeyPair(const IdentityKey &publicKey, const DjbECPrivateKey &privateKey)
{
    this->publicKey = publicKey;
    this->privateKey = privateKey;
}

IdentityKeyPair::IdentityKeyPair(const QByteArray &serialized)
{
    textsecure::IdentityKeyPairStructure structure;
    structure.ParseFromArray(serialized.constData(), serialized.size());
    ::std::string publickey = structure.publickey();
    this->publicKey  = IdentityKey(QByteArray(publickey.data(), publickey.length()), 0);
    ::std::string privatekey = structure.privatekey();
    this->privateKey = Curve::decodePrivatePoint(QByteArray(privatekey.data(), privatekey.length()));
}

IdentityKey IdentityKeyPair::getPublicKey() const
{
    return publicKey;
}

DjbECPrivateKey IdentityKeyPair::getPrivateKey() const
{
    return privateKey;
}
