#include "rootkey.h"
#include "../ecc/curve.h"
#include "../kdf/derivedrootsecrets.h"

#include <QDebug>

RootKey::RootKey()
{

}

RootKey::RootKey(const HKDF &kdf, const QByteArray &key)
{
    this->kdf = kdf;
    this->key = key;
}

QByteArray RootKey::getKeyBytes() const
{
    return key;
}

QPair<RootKey, ChainKey> RootKey::createChain(const DjbECPublicKey &theirRatchetKey, const ECKeyPair &ourRatchetKey)
{
    QByteArray sharedSecret = Curve::calculateAgreement(theirRatchetKey, ourRatchetKey.getPrivateKey());
    QByteArray derivedSecretBytes = kdf.deriveSecrets(sharedSecret, QByteArray("WhisperRatchet"), DerivedRootSecrets::SIZE, key);
    DerivedRootSecrets derivedSecrets(derivedSecretBytes);

    RootKey newRootKey(kdf, derivedSecrets.getRootKey());
    ChainKey newChainKey(kdf, derivedSecrets.getChainKey(), 0);

    QPair<RootKey, ChainKey> pair;
    pair.first = newRootKey;
    pair.second = newChainKey;

    return pair;
}
