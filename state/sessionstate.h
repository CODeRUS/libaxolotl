#ifndef SESSIONSTATE_H
#define SESSIONSTATE_H

#include "LocalStorageProtocol.pb.h"
#include "../identitykey.h"
#include "../ratchet/rootkey.h"
#include "../ratchet/chainkey.h"
#include "../identitykeypair.h"
#include "../ecc/djbec.h"

class UnacknowledgedPreKeyMessageItems
{
public:
    UnacknowledgedPreKeyMessageItems(int preKeyId, int signedPreKeyId, const DjbECPublicKey &baseKey);
    int getPreKeyId() const;
    int getSignedPreKeyId() const;
    DjbECPublicKey getBaseKey() const;

private:
    int preKeyId;
    int signedPreKeyId;
    DjbECPublicKey baseKey;
};

class SessionState
{
public:
    SessionState();
    SessionState(const textsecure::SessionStructure &sessionSctucture);
    SessionState(const SessionState &copy);

    textsecure::SessionStructure getStructure() const;
    QByteArray getAliceBaseKey() const;
    void setAliceBaseKey(const QByteArray &aliceBaseKey);
    void setSessionVersion(int version);
    int getSessionVersion() const;
    void setRemoteIdentityKey(const IdentityKey &identityKey);
    void setLocalIdentityKey(const IdentityKey &identityKey);
    bool hasRemoteIdentityKey() const;
    IdentityKey getRemoteIdentityKey() const;
    IdentityKey getLocalIdentityKey() const;
    int getPreviousCounter() const;
    void setPreviousCounter(int previousCounter);
    RootKey getRootKey() const;
    void setRootKey(const RootKey &rootKey);
    DjbECPublicKey getSenderRatchetKey() const;
    ECKeyPair getSenderRatchetKeyPair() const;
    bool hasReceiverChain(const DjbECPublicKey &senderEphemeral) const;
    bool hasSenderChain() const;
    int getReceiverChain(const DjbECPublicKey &senderEphemeral) const;
    ChainKey getReceiverChainKey(const DjbECPublicKey &senderEphemeral) const;
    void addReceiverChain(const DjbECPublicKey &senderRatchetKey, const ChainKey &chainKey);
    void setSenderChain(const ECKeyPair &senderRatchetKeyPair, const ChainKey &chainKey);
    ChainKey getSenderChainKey() const;
    void setSenderChainKey(const ChainKey &nextChainKey);
    bool hasMessageKeys(const DjbECPublicKey &senderEphemeral, uint counter) const;
    MessageKeys removeMessageKeys(const DjbECPublicKey &senderEphemeral, uint counter);
    void setMessageKeys(const DjbECPublicKey &senderEphemeral, const MessageKeys &messageKeys);
    void setReceiverChainKey(const DjbECPublicKey &senderEphemeral, const ChainKey &chainKey);
    void setPendingKeyExchange(int sequence,
                               const ECKeyPair &ourBaseKey,
                               const ECKeyPair &ourRatchetKey,
                               const IdentityKeyPair &ourIdentityKey);
    int getPendingKeyExchangeSequence() const;
    ECKeyPair getPendingKeyExchangeBaseKey() const;
    ECKeyPair getPendingKeyExchangeRatchetKey() const;
    IdentityKeyPair getPendingKeyExchangeIdentityKey() const;
    bool hasPendingKeyExchange() const;
    void setUnacknowledgedPreKeyMessage(int preKeyId, int signedPreKeyId, const DjbECPublicKey &baseKey);
    bool hasUnacknowledgedPreKeyMessage() const;
    UnacknowledgedPreKeyMessageItems getUnacknowledgedPreKeyMessageItems() const;
    void clearUnacknowledgedPreKeyMessage();
    void setRemoteRegistrationId(int registrationId);
    int getRemoteRegistrationId() const;
    void setLocalRegistrationId(int registrationId);
    int getLocalRegistrationId() const;
    QByteArray serialize() const;

private:
    textsecure::SessionStructure sessionStructure;

};

#endif // SESSIONSTATE_H
