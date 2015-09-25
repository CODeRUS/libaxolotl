#ifndef SESSIONBUILDER_H
#define SESSIONBUILDER_H

#include <QSharedPointer>

#include "state/sessionstore.h"
#include "state/signedprekeystore.h"
#include "state/prekeybundle.h"
#include "state/prekeystore.h"
#include "state/identitykeystore.h"
#include "state/axolotlstore.h"
#include "protocol/prekeywhispermessage.h"
#include "protocol/keyexchangemessage.h"
#include "axolotladdress.h"

class SessionBuilder
{
public:
    SessionBuilder();
    SessionBuilder(QSharedPointer<SessionStore> sessionStore,
                   QSharedPointer<PreKeyStore> preKeyStore,
                   QSharedPointer<SignedPreKeyStore> signedPreKeyStore,
                   QSharedPointer<IdentityKeyStore> identityKeyStore,
                   const AxolotlAddress &remoteAddress);
    SessionBuilder(QSharedPointer<AxolotlStore> store, const AxolotlAddress &remoteAddress);

    ulong process(SessionRecord *sessionRecord, QSharedPointer<PreKeyWhisperMessage> message);
    ulong processV3(SessionRecord *sessionRecord, QSharedPointer<PreKeyWhisperMessage> message);
    ulong processV2(SessionRecord *sessionRecord, QSharedPointer<PreKeyWhisperMessage> message);
    void process(const PreKeyBundle &preKey);
    KeyExchangeMessage process(QSharedPointer<KeyExchangeMessage> message);
    KeyExchangeMessage process();

private:
    void init(QSharedPointer<SessionStore> sessionStore,
              QSharedPointer<PreKeyStore> preKeyStore,
              QSharedPointer<SignedPreKeyStore> signedPreKeyStore,
              QSharedPointer<IdentityKeyStore> identityKeyStore,
              const AxolotlAddress &remoteAddress);
    KeyExchangeMessage processInitiate(QSharedPointer<KeyExchangeMessage> message);
    void processResponse(QSharedPointer<KeyExchangeMessage> message);

private:
    QSharedPointer<SessionStore>      sessionStore;
    QSharedPointer<PreKeyStore>       preKeyStore;
    QSharedPointer<SignedPreKeyStore> signedPreKeyStore;
    QSharedPointer<IdentityKeyStore>  identityKeyStore;
    AxolotlAddress                    remoteAddress;
};

#endif // SESSIONBUILDER_H
