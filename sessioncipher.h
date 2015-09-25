#ifndef SESSIONCIPHER_H
#define SESSIONCIPHER_H

#include <QSharedPointer>

#include "state/sessionstore.h"
#include "sessionbuilder.h"
#include "ratchet/messagekeys.h"
#include "axolotladdress.h"

class SessionCipher
{
public:
    SessionCipher(QSharedPointer<SessionStore> sessionStore, QSharedPointer<PreKeyStore> preKeyStore,
                  QSharedPointer<SignedPreKeyStore> signedPreKeyStore, QSharedPointer<IdentityKeyStore> identityKeyStore,
                  const AxolotlAddress &remoteAddress);
    SessionCipher(QSharedPointer<AxolotlStore> store, const AxolotlAddress &remoteAddress);
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
              const AxolotlAddress &remoteAddress);
    ChainKey getOrCreateChainKey(SessionState *sessionState, const DjbECPublicKey &theirEphemeral);
    MessageKeys getOrCreateMessageKeys(SessionState *sessionState,
                                       const DjbECPublicKey &theirEphemeral,
                                       const ChainKey &chainKey, uint counter);
    QByteArray getCiphertext(int version, const MessageKeys &messageKeys, const QByteArray &plaintext);
    QByteArray getPlaintext(int version, const MessageKeys &messageKeys, const QByteArray &cipherText);

    QSharedPointer<SessionStore>   sessionStore;
    SessionBuilder                 sessionBuilder;
    QSharedPointer<PreKeyStore>    preKeyStore;
    AxolotlAddress                 remoteAddress;
};

#endif // SESSIONCIPHER_H
