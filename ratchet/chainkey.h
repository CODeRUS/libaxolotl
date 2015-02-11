#ifndef CHAINKEY_H
#define CHAINKEY_H

#include "../kdf/hkdf.h"
#include "../ratchet/messagekeys.h"
#include "../kdf/derivedmessagesecrets.h"

class ChainKey
{
public:
    ChainKey();
    ChainKey(const HKDF &kdf, const QByteArray &key, uint index);

    QByteArray getKey() const;
    uint getIndex() const;
    QByteArray getBaseMaterial(const QByteArray &seed) const;
    ChainKey getNextChainKey() const;
    MessageKeys getMessageKeys() const;

    static const QByteArray MESSAGE_KEY_SEED;
    static const QByteArray CHAIN_KEY_SEED;

private:
    HKDF kdf;
    QByteArray key;
    uint index;

};

#endif // CHAINKEY_H
