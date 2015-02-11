#include "ratchetingsession.h"
#include "../util/byteutil.h"
#include "../ecc/curve.h"
#include "../ecc/djbec.h"

#include <QDebug>

RatchetingSession::RatchetingSession()
{
}

void RatchetingSession::initializeSession(SessionState *sessionState, int sessionVersion, const SymmetricAxolotlParameters &parameters)
{
    if (RatchetingSession::isAlice(parameters.getOurBaseKey().getPublicKey(), parameters.getTheirBaseKey())) {
        AliceAxolotlParameters aliceParameters;
        aliceParameters.setOurBaseKey(parameters.getOurBaseKey());
        aliceParameters.setOurIdentityKey(parameters.getOurIdentityKey());
        aliceParameters.setTheirRatchetKey(parameters.getTheirRatchetKey());
        aliceParameters.setTheirIdentityKey(parameters.getTheirIdentityKey());
        aliceParameters.setTheirSignedPreKey(parameters.getTheirBaseKey());

        RatchetingSession::initializeSession(sessionState, sessionVersion, aliceParameters);
    }
}

void RatchetingSession::initializeSession(SessionState *sessionState, int sessionVersion, const AliceAxolotlParameters &parameters)
{
    sessionState->setSessionVersion(sessionVersion);
    sessionState->setRemoteIdentityKey(parameters.getTheirIdentityKey());
    sessionState->setLocalIdentityKey(parameters.getOurIdentityKey().getPublicKey());

    ECKeyPair sendingRatchetKey = Curve::generateKeyPair();
    QByteArray secrets;

    if (sessionVersion >= 3) {
        secrets.append(RatchetingSession::getDiscontinuityBytes());
    }

    secrets.append(Curve::calculateAgreement(parameters.getTheirSignedPreKey(),
                                             parameters.getOurIdentityKey().getPrivateKey()));
    secrets.append(Curve::calculateAgreement(parameters.getTheirIdentityKey().getPublicKey(),
                                             parameters.getOurBaseKey().getPrivateKey()));
    secrets.append(Curve::calculateAgreement(parameters.getTheirSignedPreKey(),
                                             parameters.getOurBaseKey().getPrivateKey()));

    if (sessionVersion >= 3 && !parameters.getTheirOneTimePreKey().serialize().isEmpty()) {
        secrets.append(Curve::calculateAgreement(parameters.getTheirOneTimePreKey(),
                                                 parameters.getOurBaseKey().getPrivateKey()));
    }

    DerivedKeys              derivedKeys  = RatchetingSession::calculateDerivedKeys(sessionVersion, secrets);
    QPair<RootKey, ChainKey> sendingChain = derivedKeys.getRootKey().createChain(parameters.getTheirRatchetKey(), sendingRatchetKey);

    sessionState->addReceiverChain(parameters.getTheirRatchetKey(), derivedKeys.getChainKey());
    sessionState->setSenderChain(sendingRatchetKey, sendingChain.second);
    sessionState->setRootKey(sendingChain.first);
}

void RatchetingSession::initializeSession(SessionState *sessionState, int sessionVersion, const BobAxolotlParameters &parameters)
{
    sessionState->setSessionVersion(sessionVersion);
    sessionState->setRemoteIdentityKey(parameters.getTheirIdentityKey());
    sessionState->setLocalIdentityKey(parameters.getOurIdentityKey().getPublicKey());

    QByteArray secrets;

    if (sessionVersion >= 3) {
        secrets.append(RatchetingSession::getDiscontinuityBytes());
    }

    secrets.append(Curve::calculateAgreement(parameters.getTheirIdentityKey().getPublicKey(),
                                             parameters.getOurSignedPreKey().getPrivateKey()));
    secrets.append(Curve::calculateAgreement(parameters.getTheirBaseKey(),
                                             parameters.getOurIdentityKey().getPrivateKey()));
    secrets.append(Curve::calculateAgreement(parameters.getTheirBaseKey(),
                                             parameters.getOurSignedPreKey().getPrivateKey()));

    if (sessionVersion >= 3
            && !parameters.getOurOneTimePreKey().getPrivateKey().serialize().isEmpty()
            && !parameters.getOurOneTimePreKey().getPublicKey().serialize().isEmpty()) {
        secrets.append(Curve::calculateAgreement(parameters.getTheirBaseKey(),
                                                 parameters.getOurOneTimePreKey().getPrivateKey()));
    }

    DerivedKeys              derivedKeys  = RatchetingSession::calculateDerivedKeys(sessionVersion, secrets);

    sessionState->setSenderChain(parameters.getOurRatchetKey(), derivedKeys.getChainKey());
    sessionState->setRootKey(derivedKeys.getRootKey());
}

DerivedKeys RatchetingSession::calculateDerivedKeys(int sessionVersion, const QByteArray &masterSecret)
{
    HKDF kdf(sessionVersion);
    QByteArray derivedSecretBytes = kdf.deriveSecrets(masterSecret, QByteArray("WhisperText"), 64);
    QByteArray rootSecrets = derivedSecretBytes.left(32);
    QByteArray chainSecrets = derivedSecretBytes.mid(32, 32);
    return DerivedKeys(RootKey(kdf, rootSecrets),
                       ChainKey(kdf, chainSecrets, 0));
}

QByteArray RatchetingSession::getDiscontinuityBytes()
{
    return QByteArray(32, '\xFF');
}

bool RatchetingSession::isAlice(const DjbECPublicKey &ourKey, const DjbECPublicKey &theirKey)
{
    return ourKey.serialize() < theirKey.serialize();
}
