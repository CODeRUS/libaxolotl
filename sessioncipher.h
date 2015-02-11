#ifndef SESSIONCIPHER_H
#define SESSIONCIPHER_H

#include <QSharedPointer>

#include "state/sessionstore.h"
#include "sessionbuilder.h"
#include "ratchet/messagekeys.h"

class SessionCipher
{
public:
    SessionCipher(QSharedPointer<SessionStore> sessionStore, QSharedPointer<PreKeyStore> preKeyStore,
                  QSharedPointer<SignedPreKeyStore> signedPreKeyStore, QSharedPointer<IdentityKeyStore> identityKeyStore,
                  qulonglong recipientId, int deviceId);
    SessionCipher(QSharedPointer<AxolotlStore> store, qulonglong recipientId, int deviceId);
    QSharedPointer<CiphertextMessage> encrypt(const QByteArray &paddedMessage);
    QByteArray decrypt(QSharedPointer<PreKeyWhisperMessage> ciphertext);
    QByteArray decrypt(QSharedPointer<WhisperMessage> ciphertext);
    QByteArray decrypt(SessionRecord *sessionRecord, QSharedPointer<WhisperMessage> ciphertext);
    QByteArray decrypt(SessionState *sessionState, QSharedPointer<WhisperMessage> ciphertextMessage);
    int getRemoteRegistrationId();
    int getSessionVersion() ;

private:
    void init(QSharedPointer<SessionStore> sessionStore, QSharedPointer<PreKeyStore> preKeyStore,
              QSharedPointer<SignedPreKeyStore> signedPreKeyStore, QSharedPointer<IdentityKeyStore> identityKeyStore,
              qulonglong recipientId, int deviceId);
    ChainKey getOrCreateChainKey(SessionState *sessionState, const DjbECPublicKey &theirEphemeral);
    MessageKeys getOrCreateMessageKeys(SessionState *sessionState,
                                       const DjbECPublicKey &theirEphemeral,
                                       const ChainKey &chainKey, uint counter);
    QByteArray getCiphertext(int version, const MessageKeys &messageKeys, const QByteArray &plaintext);
    QByteArray getPlaintext(int version, const MessageKeys &messageKeys, const QByteArray &cipherText);

    QSharedPointer<SessionStore>   sessionStore;
    SessionBuilder sessionBuilder;
    QSharedPointer<PreKeyStore>    preKeyStore;
    qulonglong           recipientId;
    int            deviceId;
};

#endif // SESSIONCIPHER_H
