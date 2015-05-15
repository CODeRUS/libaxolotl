#include "sessioncipher.h"
#include "nosessionexception.h"
#include "invalidmessageexception.h"
#include "invalidkeyexception.h"
#include "duplicatemessageexception.h"

#include <QListIterator>
#include <QMutableListIterator>
#include <QByteArray>
#include <QPair>
#include <QDebug>

#include <openssl/aes.h>

static void ctr128_inc(unsigned char *counter) {
    unsigned int  n=16;
    unsigned char c;

    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c) return;
    } while (n);
}

static void ctr128_inc_aligned(unsigned char *counter) {
    size_t *data,c,n;
    const union { long one; char little; } is_endian = {1};

    if (is_endian.little) {
        ctr128_inc(counter);
        return;
    }

    data = (size_t *)counter;
    n = 16/sizeof(size_t);
    do {
        --n;
        c = data[n];
        ++c;
        data[n] = c;
        if (c) return;
    } while (n);
}

SessionCipher::SessionCipher(QSharedPointer<SessionStore> sessionStore, QSharedPointer<PreKeyStore> preKeyStore, QSharedPointer<SignedPreKeyStore> signedPreKeyStore, QSharedPointer<IdentityKeyStore> identityKeyStore, qulonglong recipientId, int deviceId)
{
    init(sessionStore, preKeyStore, signedPreKeyStore, identityKeyStore, recipientId, deviceId);
}

SessionCipher::SessionCipher(QSharedPointer<AxolotlStore> store, qulonglong recipientId, int deviceId)
{
    init(qSharedPointerCast<SessionStore>(store),
         qSharedPointerCast<PreKeyStore>(store),
         qSharedPointerCast<SignedPreKeyStore>(store),
         qSharedPointerCast<IdentityKeyStore>(store),
         recipientId, deviceId);
}

void SessionCipher::init(QSharedPointer<SessionStore> sessionStore, QSharedPointer<PreKeyStore> preKeyStore, QSharedPointer<SignedPreKeyStore> signedPreKeyStore, QSharedPointer<IdentityKeyStore> identityKeyStore, qulonglong recipientId, int deviceId)
{
    this->sessionStore   = sessionStore;
    this->recipientId    = recipientId;
    this->deviceId       = deviceId;
    this->preKeyStore    = preKeyStore;
    this->sessionBuilder = SessionBuilder(sessionStore, preKeyStore, signedPreKeyStore,
                                          identityKeyStore, recipientId, deviceId);
}

QSharedPointer<CiphertextMessage> SessionCipher::encrypt(const QByteArray &paddedMessage)
{
    QSharedPointer<CiphertextMessage> result;

    SessionRecord *sessionRecord   = sessionStore->loadSession(recipientId, deviceId);
    SessionState  *sessionState    = sessionRecord->getSessionState();
    ChainKey       chainKey        = sessionState->getSenderChainKey();
    MessageKeys    messageKeys     = chainKey.getMessageKeys();
    DjbECPublicKey senderEphemeral = sessionState->getSenderRatchetKey();
    int            previousCounter = sessionState->getPreviousCounter();
    int            sessionVersion  = sessionState->getSessionVersion();

    QByteArray     ciphertextBody  = getCiphertext(sessionVersion, messageKeys, paddedMessage);
    QSharedPointer<WhisperMessage> whisperMessage(new WhisperMessage(sessionVersion, messageKeys.getMacKey(),
                                                                     senderEphemeral, chainKey.getIndex(),
                                                                     previousCounter, ciphertextBody,
                                                                     sessionState->getLocalIdentityKey(),
                                                                     sessionState->getRemoteIdentityKey()));

    if (sessionState->hasUnacknowledgedPreKeyMessage()) {
        UnacknowledgedPreKeyMessageItems items = sessionState->getUnacknowledgedPreKeyMessageItems();
        int localRegistrationId = sessionState->getLocalRegistrationId();

        QSharedPointer<PreKeyWhisperMessage> preKeyWhisperMessage(new PreKeyWhisperMessage(
                                                                      sessionVersion, localRegistrationId, items.getPreKeyId(),
                                                                      items.getSignedPreKeyId(), items.getBaseKey(),
                                                                      sessionState->getLocalIdentityKey(),
                                                                      whisperMessage));
        result = preKeyWhisperMessage;
    }
    else {
        result = whisperMessage;
    }

    sessionState->setSenderChainKey(chainKey.getNextChainKey());
    sessionStore->storeSession(recipientId, deviceId, sessionRecord);

    return result;
}

QByteArray SessionCipher::decrypt(QSharedPointer<PreKeyWhisperMessage> ciphertext)
{
    SessionRecord    *sessionRecord    = sessionStore->loadSession(recipientId, deviceId);
    qulonglong        unsignedPreKeyId = sessionBuilder.process(sessionRecord, ciphertext);
    QByteArray        plaintext        = decrypt(sessionRecord, ciphertext->getWhisperMessage());

    sessionStore->storeSession(recipientId, deviceId, sessionRecord);

    if (unsignedPreKeyId != -1) {
        preKeyStore->removePreKey(unsignedPreKeyId);
    }

    return plaintext;
}

QByteArray SessionCipher::decrypt(QSharedPointer<WhisperMessage> ciphertext)
{
    if (!sessionStore->containsSession(recipientId, deviceId)) {
        qDebug() << "No session for" << recipientId << deviceId;
        throw NoSessionException(QString("No session for: %1, %2").arg(recipientId).arg(deviceId));
    }

    SessionRecord *sessionRecord = sessionStore->loadSession(recipientId, deviceId);
    QByteArray     plaintext     = decrypt(sessionRecord, ciphertext);

    sessionStore->storeSession(recipientId, deviceId, sessionRecord);

    return plaintext;
}

QByteArray SessionCipher::decrypt(SessionRecord *sessionRecord, QSharedPointer<WhisperMessage> ciphertext)
{
    QList<SessionState*> previousStatesList = sessionRecord->getPreviousSessionStates();
    QMutableListIterator<SessionState*> previousStates(previousStatesList);
    QList<WhisperException> exceptions;

    try {
        SessionState *sessionState = sessionRecord->getSessionState();
        QByteArray    plaintext    = decrypt(sessionState, ciphertext);

        sessionRecord->setState(sessionState);
        return plaintext;
    } catch (const InvalidMessageException &e) {
        exceptions.append(e);
    }

    while (previousStates.hasNext()) {
        try {
            SessionState *promotedState = previousStates.next();
            QByteArray    plaintext     = decrypt(promotedState, ciphertext);

            previousStates.remove();
            sessionRecord->promoteState(promotedState);

            return plaintext;
        } catch (const InvalidMessageException &e) {
            exceptions.append(e);
        }
    }

    throw InvalidMessageException("No valid sessions.", exceptions);
}

QByteArray SessionCipher::decrypt(SessionState *sessionState, QSharedPointer<WhisperMessage> ciphertextMessage)
{
    if (!sessionState->hasSenderChain()) {
        throw InvalidMessageException("Uninitialized session!");
    }

    if (ciphertextMessage->getMessageVersion() != sessionState->getSessionVersion()) {
        throw InvalidMessageException(QString("Message version %1, but session version %2")
                                          .arg(ciphertextMessage->getMessageVersion())
                                          .arg(sessionState->getSessionVersion()));
    }

    int            messageVersion    = ciphertextMessage->getMessageVersion();
    DjbECPublicKey theirEphemeral    = ciphertextMessage->getSenderRatchetKey();
    uint           counter           = ciphertextMessage->getCounter();
    ChainKey       chainKey          = getOrCreateChainKey(sessionState, theirEphemeral);
    MessageKeys    messageKeys       = getOrCreateMessageKeys(sessionState, theirEphemeral,
                                                              chainKey, counter);

    ciphertextMessage->verifyMac(messageVersion,
                                 sessionState->getRemoteIdentityKey(),
                                 sessionState->getLocalIdentityKey(),
                                 messageKeys.getMacKey());

    QByteArray plaintext = getPlaintext(messageVersion, messageKeys, ciphertextMessage->getBody());

    sessionState->clearUnacknowledgedPreKeyMessage();

    return plaintext;
}

int SessionCipher::getRemoteRegistrationId()
{
    SessionRecord *record = sessionStore->loadSession(recipientId, deviceId);
    return record->getSessionState()->getRemoteRegistrationId();
}

int SessionCipher::getSessionVersion()
{
    if (!sessionStore->containsSession(recipientId, deviceId)) {
        qDebug() << "No session for" << recipientId << deviceId;
        throw NoSessionException(QString("No session for (%1, %2)!").arg(recipientId).arg(deviceId));
    }

    SessionRecord *record = sessionStore->loadSession(recipientId, deviceId);
    return record->getSessionState()->getSessionVersion();
}

ChainKey SessionCipher::getOrCreateChainKey(SessionState *sessionState, const DjbECPublicKey &theirEphemeral)
{
    try {
        if (sessionState->hasReceiverChain(theirEphemeral)) {
            return sessionState->getReceiverChainKey(theirEphemeral);
        } else {
            RootKey                  rootKey         = sessionState->getRootKey();
            ECKeyPair                ourEphemeral    = sessionState->getSenderRatchetKeyPair();
            QPair<RootKey, ChainKey> receiverChain   = rootKey.createChain(theirEphemeral, ourEphemeral);
            ECKeyPair                ourNewEphemeral = Curve::generateKeyPair();
            QPair<RootKey, ChainKey> senderChain     = receiverChain.first.createChain(theirEphemeral, ourNewEphemeral);

            sessionState->setRootKey(senderChain.first);
            sessionState->addReceiverChain(theirEphemeral, receiverChain.second);
            sessionState->setPreviousCounter(qMax(sessionState->getSenderChainKey().getIndex() - 1, (uint)0));
            sessionState->setSenderChain(ourNewEphemeral, senderChain.second);

            return receiverChain.second;
        }
    } catch (const InvalidKeyException &e) {
        throw InvalidMessageException(__PRETTY_FUNCTION__, QList<WhisperException>() << e);
    }
}

MessageKeys SessionCipher::getOrCreateMessageKeys(SessionState *sessionState, const DjbECPublicKey &theirEphemeral, const ChainKey &chainKey, uint counter)
{
    if (chainKey.getIndex() > counter) {
        if (sessionState->hasMessageKeys(theirEphemeral, counter)) {
            return sessionState->removeMessageKeys(theirEphemeral, counter);
        } else {
            throw DuplicateMessageException(QString("Received message with old counter: %1, %2")
                                                .arg(chainKey.getIndex())
                                                .arg(counter));
        }
    }

    if (counter - chainKey.getIndex() > 2000) {
        throw InvalidMessageException("Over 2000 messages into the future!");
    }

    ChainKey nowChainKey = chainKey;
    while (nowChainKey.getIndex() < counter) {
        MessageKeys messageKeys = nowChainKey.getMessageKeys();
        sessionState->setMessageKeys(theirEphemeral, messageKeys);
        nowChainKey = nowChainKey.getNextChainKey();
    }

    sessionState->setReceiverChainKey(theirEphemeral, nowChainKey.getNextChainKey());
    return nowChainKey.getMessageKeys();
}

QByteArray SessionCipher::getCiphertext(int version, const MessageKeys &messageKeys, const QByteArray &plaintext)
{
    AES_KEY enc_key;
    QByteArray key = messageKeys.getCipherKey();
    if (version >= 3) {
        AES_set_encrypt_key((const unsigned char*)key.constData(), key.size() * 8, &enc_key);
        QByteArray padText = plaintext;
        int padlen = ((padText.size() + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE - plaintext.size();
        padText.append(QByteArray(padlen, (char)padlen));
        QByteArray out(padText.size(), '\0');
        QByteArray ivec(messageKeys.getIv());
        AES_cbc_encrypt((const unsigned char*)padText.constData(), (unsigned char*)out.data(),
                        padText.size(), &enc_key,
                        (unsigned char*)ivec.data(), AES_ENCRYPT);
        return out;
    } else {
        AES_set_encrypt_key((const unsigned char*)key.constData(), 128, &enc_key);
        QByteArray out(plaintext.size(), '\0');
        unsigned int counter = 0;
        QByteArray iv(AES_BLOCK_SIZE, '\0');
        //ByteUtil::intToByteArray(iv, 0, counter);
        unsigned char ecount[AES_BLOCK_SIZE];
        memset(ecount, 0, AES_BLOCK_SIZE);
        // TODO store state
        for (unsigned int i = 0; i < messageKeys.getCounter(); i++) {
            AES_encrypt((const unsigned char*)iv.constData(), ecount, &enc_key);
            ctr128_inc_aligned((unsigned char*)iv.data());
        }
        AES_ctr128_encrypt((const unsigned char*)plaintext.constData(), (unsigned char*)out.data(),
                           plaintext.size(), &enc_key, (unsigned char*)iv.data(),
                           ecount, &counter);
        return out;
    }
}

QByteArray SessionCipher::getPlaintext(int version, const MessageKeys &messageKeys, const QByteArray &cipherText)
{
    qDebug() << version << cipherText.toHex();
    AES_KEY dec_key;
    QByteArray key = messageKeys.getCipherKey();
    QByteArray out(cipherText.size(), '\0');
    if (version >= 3) {
        AES_set_decrypt_key((const unsigned char*)key.constData(), key.size() * 8, &dec_key);
        QByteArray ivec(messageKeys.getIv());
        AES_cbc_encrypt((const unsigned char*)cipherText.constData(),
                        (unsigned char*)out.data(),
                        cipherText.size(), &dec_key,
                        (unsigned char*)ivec.data(), AES_DECRYPT);
        out = out.mid(0, out.size() - out.right(1)[0]);
    } else {
        AES_set_encrypt_key((const unsigned char*)key.constData(), 128, &dec_key);
        unsigned int counter = 0;
        QByteArray iv(AES_BLOCK_SIZE, '\0');
        //ByteUtil::intToByteArray(iv, 0, counter);
        unsigned char ecount[AES_BLOCK_SIZE];
        memset(ecount, 0, AES_BLOCK_SIZE);
        for (unsigned int i = 0; i < messageKeys.getCounter(); i++) {
            AES_encrypt((const unsigned char*)iv.constData(), ecount, &dec_key);
            ctr128_inc_aligned((unsigned char*)iv.data());
        }
        AES_ctr128_encrypt((const unsigned char*)cipherText.constData(), (unsigned char*)out.data(),
                           cipherText.size(), &dec_key, (unsigned char*)iv.data(),
                           ecount, &counter);
    }
    return out;
}
