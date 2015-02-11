#include "chainkey.h"
#include <QMessageAuthenticationCode>
#include <QDebug>

const QByteArray ChainKey::MESSAGE_KEY_SEED = QByteArray("\x01");
const QByteArray ChainKey::CHAIN_KEY_SEED = QByteArray("\x02");

ChainKey::ChainKey()
{

}

ChainKey::ChainKey(const HKDF &kdf, const QByteArray &key, uint index)
{
    this->kdf = kdf;
    this->key = key;
    this->index = index;
}

QByteArray ChainKey::getKey() const
{
    return key;
}

uint ChainKey::getIndex() const
{
    return index;
}

QByteArray ChainKey::getBaseMaterial(const QByteArray &seed) const
{
    return QMessageAuthenticationCode::hash(seed, key, QCryptographicHash::Sha256);
}

ChainKey ChainKey::getNextChainKey() const
{
    QByteArray nextKey = getBaseMaterial(CHAIN_KEY_SEED);
    return ChainKey(kdf, nextKey, index + 1);
}

MessageKeys ChainKey::getMessageKeys() const
{
    QByteArray inputKeyMaterial = getBaseMaterial(MESSAGE_KEY_SEED);
    QByteArray keyMaterialBytes = kdf.deriveSecrets(inputKeyMaterial, QByteArray("WhisperMessageKeys"), DerivedMessageSecrets::SIZE);
    DerivedMessageSecrets keyMaterial(keyMaterialBytes);
    return MessageKeys(keyMaterial.getCipherKey(), keyMaterial.getMacKey(), keyMaterial.getIv(), index);
}
