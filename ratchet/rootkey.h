#ifndef ROOTKEY_H
#define ROOTKEY_H

#include "../kdf/hkdf.h"
#include "chainkey.h"
#include "../ecc/eckeypair.h"

#include <QByteArray>
#include <QPair>

class RootKey
{
public:
    RootKey();
    RootKey(const HKDF &kdf, const QByteArray &key);

    QByteArray getKeyBytes() const;
    QPair<RootKey, ChainKey> createChain(const DjbECPublicKey &theirRatchetKey, const ECKeyPair &ourRatchetKey);

private:
    HKDF kdf;
    QByteArray key;

};

#endif // ROOTKEY_H
