#include "sessionstate.h"
#include "../ecc/curve.h"
#include "../invalidkeyexception.h"

#include <QPair>

UnacknowledgedPreKeyMessageItems::UnacknowledgedPreKeyMessageItems(int preKeyId, int signedPreKeyId, const DjbECPublicKey &baseKey)
{
    this->preKeyId       = preKeyId;
    this->signedPreKeyId = signedPreKeyId;
    this->baseKey        = baseKey;
}

int UnacknowledgedPreKeyMessageItems::getPreKeyId() const
{
    return preKeyId;
}

int UnacknowledgedPreKeyMessageItems::getSignedPreKeyId() const
{
    return signedPreKeyId;
}

DjbECPublicKey UnacknowledgedPreKeyMessageItems::getBaseKey() const
{
    return baseKey;
}

SessionState::SessionState()
{
    this->sessionStructure.Clear();
}

SessionState::SessionState(const textsecure::SessionStructure &sessionSctucture)
{
    this->sessionStructure.CopyFrom(sessionSctucture);
}

SessionState::SessionState(const SessionState &copy)
{
    this->sessionStructure.CopyFrom(copy.getStructure());
}

textsecure::SessionStructure SessionState::getStructure() const
{
    return sessionStructure;
}

QByteArray SessionState::getAliceBaseKey() const
{
    ::std::string alicebasekey = sessionStructure.alicebasekey();
    QByteArray bytes(alicebasekey.data(), alicebasekey.size());
    return bytes;
}

void SessionState::setAliceBaseKey(const QByteArray &aliceBaseKey)
{
    sessionStructure.set_alicebasekey(aliceBaseKey.constData(), aliceBaseKey.size());
}

void SessionState::setSessionVersion(int version)
{
    sessionStructure.set_sessionversion(version);
}

int SessionState::getSessionVersion() const
{
    int sessionVersion = sessionStructure.sessionversion();

    if (sessionVersion == 0) return 2;
    else                     return sessionVersion;
}

void SessionState::setRemoteIdentityKey(const IdentityKey &identityKey)
{
    QByteArray byteKey = identityKey.serialize();
    sessionStructure.set_remoteidentitypublic(byteKey.constData(), byteKey.size());
}

void SessionState::setLocalIdentityKey(const IdentityKey &identityKey)
{
    QByteArray byteKey = identityKey.serialize();
    sessionStructure.set_localidentitypublic(byteKey.constData(), byteKey.size());
}

bool SessionState::hasRemoteIdentityKey() const
{
    return sessionStructure.has_remoteidentitypublic();
}

IdentityKey SessionState::getRemoteIdentityKey() const
{
    if (!sessionStructure.has_remoteidentitypublic()) {
        throw InvalidKeyException("No RemoteIdentityKey");
    }
    else {
        ::std::string remoteidentitypublic = sessionStructure.remoteidentitypublic();
        return IdentityKey(QByteArray(remoteidentitypublic.data(), remoteidentitypublic.length()), 0);
    }
}

IdentityKey SessionState::getLocalIdentityKey() const
{
    ::std::string localidentitypublic = sessionStructure.localidentitypublic();
    return IdentityKey(QByteArray(localidentitypublic.data(), localidentitypublic.length()), 0);
}

int SessionState::getPreviousCounter() const
{
    return sessionStructure.previouscounter();
}

void SessionState::setPreviousCounter(int previousCounter)
{
    sessionStructure.set_previouscounter(previousCounter);
}

RootKey SessionState::getRootKey() const
{
    ::std::string rootkey = sessionStructure.rootkey();
    return RootKey(HKDF(getSessionVersion()), QByteArray(rootkey.data(), rootkey.length()));
}

void SessionState::setRootKey(const RootKey &rootKey)
{
    QByteArray bytesKey = rootKey.getKeyBytes();
    sessionStructure.set_rootkey(bytesKey.constData(), bytesKey.size());
}

DjbECPublicKey SessionState::getSenderRatchetKey() const
{
    ::std::string senderratchetkey = sessionStructure.senderchain().senderratchetkey();
    return Curve::decodePoint(QByteArray(senderratchetkey.data(), senderratchetkey.length()), 0);
}

ECKeyPair SessionState::getSenderRatchetKeyPair() const
{
    DjbECPublicKey  publicKey  = getSenderRatchetKey();
    ::std::string senderratchetkeyprivate = sessionStructure.senderchain().senderratchetkeyprivate();
    DjbECPrivateKey privateKey = Curve::decodePrivatePoint(QByteArray(senderratchetkeyprivate.data(),
                                                                   senderratchetkeyprivate.length()));

    return ECKeyPair(publicKey, privateKey);
}

bool SessionState::hasReceiverChain(const DjbECPublicKey &senderEphemeral)
{
    return getReceiverChain(senderEphemeral) != -1;
}

bool SessionState::hasSenderChain() const
{
    return sessionStructure.has_senderchain();
}

int SessionState::getReceiverChain(const DjbECPublicKey &senderEphemeral)
{
    for (int i = 0; i < sessionStructure.receiverchains_size(); i++) {
        textsecure::SessionStructure::Chain *receiverChain = sessionStructure.mutable_receiverchains(i);
        if (receiverChain && receiverChain->has_senderratchetkey()) {
            ::std::string senderratchetkey = receiverChain->senderratchetkey();
            QByteArray senderratchetkeybytes(senderratchetkey.data(), senderratchetkey.length());
            DjbECPublicKey chainSenderRatchetKey = Curve::decodePoint(senderratchetkeybytes, 0);
            if (chainSenderRatchetKey == senderEphemeral) {
                return i;
            }
            else {

            }
        }
    }
    return -1;
}

ChainKey SessionState::getReceiverChainKey(const DjbECPublicKey &senderEphemeral)
{
    int receiverChainIndex = getReceiverChain(senderEphemeral);

    if (receiverChainIndex == -1) {
        throw InvalidKeyException("ReceiverChain empty");
    } else {
        textsecure::SessionStructure::Chain receiverChain = sessionStructure.receiverchains(receiverChainIndex);
        ::std::string keyfromchain = receiverChain.chainkey().key();
        return ChainKey(HKDF(getSessionVersion()),
                        QByteArray(keyfromchain.data(), keyfromchain.length()),
                        receiverChain.chainkey().index());
    }
}

void SessionState::addReceiverChain(const DjbECPublicKey &senderRatchetKey, const ChainKey &chainKey)
{
    textsecure::SessionStructure::Chain::ChainKey chainKeyStructure;
    QByteArray byteChain = chainKey.getKey();
    chainKeyStructure.set_key(byteChain.constData(), byteChain.size());
    chainKeyStructure.set_index(chainKey.getIndex());

    textsecure::SessionStructure::Chain chain;
    chain.mutable_chainkey()->CopyFrom(chainKeyStructure);
    QByteArray byteRatchet = senderRatchetKey.serialize();
    chain.set_senderratchetkey(byteRatchet.constData(), byteRatchet.size());

    sessionStructure.add_receiverchains()->CopyFrom(chain);

    if (sessionStructure.receiverchains_size() > 5) {
        delete sessionStructure.mutable_receiverchains(0);
    }
}

void SessionState::setSenderChain(const ECKeyPair &senderRatchetKeyPair, const ChainKey &chainKey)
{
    QByteArray serializedPublicKey = senderRatchetKeyPair.getPublicKey().serialize();
    QByteArray serializedPrivateKey = senderRatchetKeyPair.getPrivateKey().serialize();
    QByteArray serializedChainKey = chainKey.getKey();

    sessionStructure.mutable_senderchain()->set_senderratchetkey(serializedPublicKey.constData(), serializedPublicKey.size());
    sessionStructure.mutable_senderchain()->set_senderratchetkeyprivate(serializedPrivateKey.constData(), serializedPrivateKey.size());
    sessionStructure.mutable_senderchain()->mutable_chainkey()->set_key(serializedChainKey.constData(), serializedChainKey.size());
    sessionStructure.mutable_senderchain()->mutable_chainkey()->set_index(chainKey.getIndex());

    /*textsecure::SessionStructure::Chain::ChainKey chainKeyStructure;
    chainKeyStructure.set_key(chainKey.getKey().constData());
    chainKeyStructure.set_index(chainKey.getIndex());

    textsecure::SessionStructure::Chain senderChain;
    senderChain.set_senderratchetkey(senderRatchetKeyPair.getPublicKey().serialize().constData());
    senderChain.set_senderratchetkeyprivate(senderRatchetKeyPair.getPrivateKey().serialize().constData());
    senderChain.mutable_chainkey()->CopyFrom(chainKeyStructure);

    sessionStructure.mutable_senderchain()->CopyFrom(senderChain);*/
}

ChainKey SessionState::getSenderChainKey() const
{
    textsecure::SessionStructure::Chain::ChainKey chainKeyStructure = sessionStructure.senderchain().chainkey();
    ::std::string key = chainKeyStructure.key();
    return ChainKey(HKDF(getSessionVersion()),
                    QByteArray(key.data(), key.length()),
                    chainKeyStructure.index());
}

void SessionState::setSenderChainKey(const ChainKey &nextChainKey)
{
    QByteArray serializedChainKey = nextChainKey.getKey();

    sessionStructure.mutable_senderchain()->mutable_chainkey()->set_key(serializedChainKey.constData(), serializedChainKey.size());
    sessionStructure.mutable_senderchain()->mutable_chainkey()->set_index(nextChainKey.getIndex());

    /*textsecure::SessionStructure::Chain::ChainKey chainKey;
    chainKey.set_key(nextChainKey.getKey().constData());
    chainKey.set_index(nextChainKey.getIndex());

    textsecure::SessionStructure::Chain chain = sessionStructure.senderchain();
    chain.mutable_chainkey()->CopyFrom(chainKey);

    sessionStructure.mutable_senderchain()->CopyFrom(chain);*/
}

bool SessionState::hasMessageKeys(const DjbECPublicKey &senderEphemeral, uint counter)
{
    int chainIndex = getReceiverChain(senderEphemeral);

    if (chainIndex == -1) {
        return false;
    }

    textsecure::SessionStructure::Chain receiverChain = sessionStructure.receiverchains(chainIndex);
    for (int i = 0; i < receiverChain.messagekeys_size(); i++) {
        textsecure::SessionStructure::Chain::MessageKey messageKey = receiverChain.messagekeys(i);
        if (messageKey.index() == counter) {
            return true;
        }
    }

    return false;
}

MessageKeys SessionState::removeMessageKeys(const DjbECPublicKey &senderEphemeral, uint counter)
{
    int chainIndex = getReceiverChain(senderEphemeral);

    if (chainIndex == -1) {
        throw InvalidKeyException("ReceiverChain empty");
    }

    textsecure::SessionStructure::Chain chain = sessionStructure.receiverchains(chainIndex);
    MessageKeys result;

    for (int i = 0; i < chain.messagekeys_size(); i++) {
        textsecure::SessionStructure::Chain::MessageKey *messageKey = chain.mutable_messagekeys(i);
        if (messageKey->index() == counter) {
            ::std::string cipherkey = messageKey->cipherkey();
            ::std::string mackey = messageKey->mackey();
            ::std::string iv = messageKey->iv();
            result = MessageKeys(QByteArray(cipherkey.data(), cipherkey.length()),
                                 QByteArray(mackey.data(), mackey.length()),
                                 QByteArray(iv.data(), iv.length()),
                                 messageKey->index());
            delete messageKey;
            break;
        }
    }

    textsecure::SessionStructure::Chain *updatedChain = sessionStructure.mutable_receiverchains(chainIndex);
    updatedChain->clear_messagekeys();
    updatedChain->CopyFrom(chain);

    return result;
}

void SessionState::setMessageKeys(const DjbECPublicKey &senderEphemeral, const MessageKeys &messageKeys)
{
    int chainIndex = getReceiverChain(senderEphemeral);

    textsecure::SessionStructure::Chain *chain = (chainIndex == -1) ? sessionStructure.add_receiverchains() : sessionStructure.mutable_receiverchains(chainIndex);
    textsecure::SessionStructure::Chain::MessageKey *messageKeyStructure = chain->add_messagekeys();
    QByteArray byteCipher = messageKeys.getCipherKey();
    messageKeyStructure->set_cipherkey(byteCipher.constData(), byteCipher.size());
    QByteArray byteMac = messageKeys.getMacKey();
    messageKeyStructure->set_mackey(byteMac.constData(), byteMac.size());
    messageKeyStructure->set_index(messageKeys.getCounter());
    QByteArray byteIv = messageKeys.getIv();
    messageKeyStructure->set_iv(byteIv.constData(), byteIv.size());
}

void SessionState::setReceiverChainKey(const DjbECPublicKey &senderEphemeral, const ChainKey &chainKey)
{
    int chainIndex = getReceiverChain(senderEphemeral);
    textsecure::SessionStructure::Chain *chain =  (chainIndex == -1) ? sessionStructure.add_receiverchains() : sessionStructure.mutable_receiverchains(chainIndex);

    QByteArray serializedChainKey = chainKey.getKey();

    chain->mutable_chainkey()->set_key(serializedChainKey.constData(), serializedChainKey.size());
    chain->mutable_chainkey()->set_index(chainKey.getIndex());

    /*textsecure::SessionStructure::Chain::ChainKey chainKeyStructure;
    chainKeyStructure.set_key(chainKey.getKey().constData());
    chainKeyStructure.set_index(chainKey.getIndex());

    chain->mutable_chainkey()->CopyFrom(chainKeyStructure);*/
}

void SessionState::setPendingKeyExchange(int sequence, const ECKeyPair &ourBaseKey, const ECKeyPair &ourRatchetKey, const IdentityKeyPair &ourIdentityKey)
{
    sessionStructure.mutable_pendingkeyexchange()->set_sequence(sequence);
    sessionStructure.mutable_pendingkeyexchange()->set_localbasekey(ourBaseKey.getPublicKey().serialize().constData(),
                                                                    ourBaseKey.getPublicKey().serialize().size());
    sessionStructure.mutable_pendingkeyexchange()->set_localbasekeyprivate(ourBaseKey.getPrivateKey().serialize().constData(),
                                                                           ourBaseKey.getPrivateKey().serialize().size());
    sessionStructure.mutable_pendingkeyexchange()->set_localratchetkey(ourRatchetKey.getPublicKey().serialize().constData(),
                                                                       ourRatchetKey.getPublicKey().serialize().size());
    sessionStructure.mutable_pendingkeyexchange()->set_localratchetkeyprivate(ourRatchetKey.getPrivateKey().serialize().constData(),
                                                                              ourRatchetKey.getPrivateKey().serialize().size());
    sessionStructure.mutable_pendingkeyexchange()->set_localidentitykey(ourIdentityKey.getPublicKey().serialize().constData(),
                                                                        ourIdentityKey.getPublicKey().serialize().size());
    sessionStructure.mutable_pendingkeyexchange()->set_localidentitykeyprivate(ourIdentityKey.getPrivateKey().serialize().constData(),
                                                                               ourIdentityKey.getPrivateKey().serialize().size());


    /*textsecure::SessionStructure::PendingKeyExchange structure;
    structure.set_sequence(sequence);
    structure.set_localbasekey(ourBaseKey.getPublicKey().serialize().constData());
    structure.set_localbasekeyprivate(ourBaseKey.getPrivateKey().serialize().constData());
    structure.set_localratchetkey(ourRatchetKey.getPublicKey().serialize().constData());
    structure.set_localratchetkeyprivate(ourRatchetKey.getPrivateKey().serialize().constData());
    structure.set_localidentitykey(ourIdentityKey.getPublicKey().serialize().constData());
    structure.set_localidentitykeyprivate(ourIdentityKey.getPrivateKey().serialize().constData());
    sessionStructure.mutable_pendingkeyexchange()->CopyFrom(structure);*/
}

int SessionState::getPendingKeyExchangeSequence() const
{
    return sessionStructure.pendingkeyexchange().sequence();
}

ECKeyPair SessionState::getPendingKeyExchangeBaseKey() const
{
    ::std::string localbasekey = sessionStructure.pendingkeyexchange().localbasekey();
    DjbECPublicKey publicKey   = Curve::decodePoint(QByteArray(localbasekey.data(), localbasekey.length()), 0);
    ::std::string localbasekeyprivate = sessionStructure.pendingkeyexchange().localbasekeyprivate();
    DjbECPrivateKey privateKey = Curve::decodePrivatePoint(QByteArray(localbasekeyprivate.data(), localbasekeyprivate.length()));

    return ECKeyPair(publicKey, privateKey);
}

ECKeyPair SessionState::getPendingKeyExchangeRatchetKey() const
{
    ::std::string localratchetkey = sessionStructure.pendingkeyexchange().localratchetkey();
    DjbECPublicKey publicKey   = Curve::decodePoint(QByteArray(localratchetkey.data(), localratchetkey.length()), 0);
    ::std::string localratchetkeyprivate = sessionStructure.pendingkeyexchange().localratchetkeyprivate();
    DjbECPrivateKey privateKey = Curve::decodePrivatePoint(QByteArray(localratchetkeyprivate.data(), localratchetkeyprivate.length()));

    return ECKeyPair(publicKey, privateKey);
}

IdentityKeyPair SessionState::getPendingKeyExchangeIdentityKey() const
{
    IdentityKey publicKey(QByteArray(sessionStructure.pendingkeyexchange().localidentitykey().data(),
                                     sessionStructure.pendingkeyexchange().localidentitykey().length()), 0);

    DjbECPrivateKey privateKey = Curve::decodePrivatePoint(QByteArray(sessionStructure.pendingkeyexchange().localidentitykeyprivate().data(),
                                                                   sessionStructure.pendingkeyexchange().localidentitykeyprivate().length()));

    return IdentityKeyPair(publicKey, privateKey);
}

bool SessionState::hasPendingKeyExchange() const
{
    return sessionStructure.has_pendingkeyexchange();
}

void SessionState::setUnacknowledgedPreKeyMessage(int preKeyId, int signedPreKeyId, const DjbECPublicKey &baseKey)
{
    sessionStructure.mutable_pendingprekey()->set_signedprekeyid(signedPreKeyId);
    QByteArray byteKey = baseKey.serialize();
    sessionStructure.mutable_pendingprekey()->set_basekey(byteKey.constData(), byteKey.size());

    if (preKeyId > -1) {
        sessionStructure.mutable_pendingprekey()->set_prekeyid(preKeyId);
    }
}

bool SessionState::hasUnacknowledgedPreKeyMessage() const
{
    return sessionStructure.has_pendingprekey();
}

UnacknowledgedPreKeyMessageItems SessionState::getUnacknowledgedPreKeyMessageItems() const
{
    int preKeyId = -1;

    if (sessionStructure.pendingprekey().has_prekeyid()) {
        preKeyId = sessionStructure.pendingprekey().prekeyid();
    }

    ::std::string basekey = sessionStructure.pendingprekey().basekey();
    return UnacknowledgedPreKeyMessageItems(preKeyId,
                                            sessionStructure.pendingprekey().signedprekeyid(),
                                            Curve::decodePoint(QByteArray(basekey.data(),
                                                                          basekey.length()), 0));
}

void SessionState::clearUnacknowledgedPreKeyMessage()
{
    sessionStructure.clear_pendingprekey();
}

void SessionState::setRemoteRegistrationId(int registrationId)
{
    sessionStructure.set_remoteregistrationid(registrationId);
}

int SessionState::getRemoteRegistrationId() const
{
    return sessionStructure.remoteregistrationid();
}

void SessionState::setLocalRegistrationId(int registrationId)
{
    sessionStructure.set_localregistrationid(registrationId);
}

int SessionState::getLocalRegistrationId() const
{
    return sessionStructure.localregistrationid();
}

QByteArray SessionState::serialize() const
{
    ::std::string serialized = sessionStructure.SerializeAsString();
    return QByteArray(serialized.data(), serialized.length());
}
