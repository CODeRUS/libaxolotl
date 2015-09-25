#ifndef SENDERKEYSTATE_H
#define SENDERKEYSTATE_H

#include "../../state/LocalStorageProtocol.pb.h"
#include "../../ecc/eckeypair.h"
#include "../ratchet/senderchainkey.h"

class SenderKeyState
{
public:
    static const int MAX_MESSAGE_KEYS = 2000;

    SenderKeyState();
    SenderKeyState(int id, int iteration, const QByteArray &chainKey, const DjbECPublicKey &signatureKey);
    SenderKeyState(int id, int iteration, const QByteArray &chainKey, const ECKeyPair &signatureKey);
    SenderKeyState(int id, int iteration, const QByteArray &chainKey,
                   const DjbECPublicKey &signatureKeyPublic, const DjbECPrivateKey &signatureKeyPrivate);
    SenderKeyState(const textsecure::SenderKeyStateStructure &senderKeyStateStructure);

    int getKeyId() const;
    SenderChainKey getSenderChainKey() const;
    void setSenderChainKey(const SenderChainKey &chainKey);
    DjbECPublicKey getSigningKeyPublic() const;
    DjbECPrivateKey getSigningKeyPrivate() const;
    bool hasSenderMessageKey(uint32_t iteration) const;
    void addSenderMessageKey(const SenderMessageKey &senderMessageKey);
    SenderMessageKey removeSenderMessageKey(uint32_t iteration);
    textsecure::SenderKeyStateStructure getStructure() const;

private:
    textsecure::SenderKeyStateStructure senderKeyStateStructure;
};

#endif // SENDERKEYSTATE_H
