#include "prekeywhispermessage.h"
#include "../invalidkeyexception.h"
#include "../legacymessageexception.h"
#include "../invalidmessageexception.h"
#include "../invalidversionexception.h"

#include "../util/byteutil.h"
#include "../ecc/curve.h"
#include "WhisperTextProtocol.pb.h"

#include <QDebug>

PreKeyWhisperMessage::PreKeyWhisperMessage(const QByteArray &serialized)
{
    try {
        this->version = ByteUtil::highBitsToInt(serialized[0]);

        if (this->version > CiphertextMessage::CURRENT_VERSION) {
            throw InvalidVersionException("Unknown version: " + this->version);
        }
        textsecure::PreKeyWhisperMessage preKeyWhisperMessage;
        QByteArray serializedMessage = serialized.mid(1);
        preKeyWhisperMessage.ParseFromArray(serializedMessage.constData(), serializedMessage.size());

        if ((version == 2 && !preKeyWhisperMessage.has_prekeyid())        ||
            (version == 3 && !preKeyWhisperMessage.has_signedprekeyid())  ||
            !preKeyWhisperMessage.has_basekey()                           ||
            !preKeyWhisperMessage.has_identitykey()                       ||
            !preKeyWhisperMessage.has_message())
        {
            qDebug() << "version:" << version;
            qDebug() << "has_prekeyid:" << preKeyWhisperMessage.has_prekeyid();
            qDebug() << "has_signedprekeyid:" << preKeyWhisperMessage.has_signedprekeyid();
            qDebug() << "has_basekey:" << preKeyWhisperMessage.has_basekey();
            qDebug() << "has_identitykey:" << preKeyWhisperMessage.has_identitykey();
            qDebug() << "has_message:" << preKeyWhisperMessage.has_message();
            throw InvalidMessageException("Incomplete message.");
        }

        this->serialized     = serialized;
        this->registrationId = preKeyWhisperMessage.registrationid();
        this->preKeyId       = preKeyWhisperMessage.has_prekeyid() ? preKeyWhisperMessage.prekeyid() : -1;
        this->signedPreKeyId = preKeyWhisperMessage.has_signedprekeyid() ? preKeyWhisperMessage.signedprekeyid() : -1;
        ::std::string basekey = preKeyWhisperMessage.basekey();
        this->baseKey        = Curve::decodePoint(QByteArray(basekey.data(), basekey.length()), 0);
        ::std::string identitykey = preKeyWhisperMessage.identitykey();
        this->identityKey    = IdentityKey(Curve::decodePoint(QByteArray(identitykey.data(), identitykey.length()), 0));
        ::std::string whisperMessage = preKeyWhisperMessage.message();
        QByteArray whisperMessageSerialized(whisperMessage.data(), whisperMessage.length());
        this->message.reset(new WhisperMessage(whisperMessageSerialized));
    } catch (const InvalidKeyException &e) {
        throw InvalidMessageException(__PRETTY_FUNCTION__, QList<WhisperException>() << e);
    } catch (const LegacyMessageException &e) {
        throw InvalidMessageException(__PRETTY_FUNCTION__, QList<WhisperException>() << e);
    }
}

PreKeyWhisperMessage::PreKeyWhisperMessage(int messageVersion, ulong registrationId, ulong preKeyId, ulong signedPreKeyId, const DjbECPublicKey &baseKey, const IdentityKey &identityKey, QSharedPointer<WhisperMessage> message)
{
    this->version        = messageVersion;
    this->registrationId = registrationId;
    this->preKeyId       = preKeyId;
    this->signedPreKeyId = signedPreKeyId;
    this->baseKey        = baseKey;
    this->identityKey    = identityKey;
    this->message        = message;

    textsecure::PreKeyWhisperMessage preKeyWhisperMessage;
    preKeyWhisperMessage.set_signedprekeyid(signedPreKeyId);
    QByteArray basekey = baseKey.serialize();
    preKeyWhisperMessage.set_basekey(basekey.constData(), basekey.size());
    QByteArray identitykey = identityKey.serialize();
    preKeyWhisperMessage.set_identitykey(identitykey.constData(), identitykey.size());
    QByteArray bytemessage = message->serialize();
    preKeyWhisperMessage.set_message(bytemessage.constData(), bytemessage.size());
    preKeyWhisperMessage.set_registrationid(registrationId);

    if (preKeyId >= 0) {
        preKeyWhisperMessage.set_prekeyid(preKeyId);
    }

    ::std::string serializedmessage = preKeyWhisperMessage.SerializeAsString();
    QByteArray messageBytes = QByteArray(serializedmessage.data(), serializedmessage.length());

    this->serialized = messageBytes;
    this->serialized.prepend(ByteUtil::intsToByteHighAndLow(this->version, CURRENT_VERSION));
}

int PreKeyWhisperMessage::getMessageVersion() const
{
    return version;
}

IdentityKey PreKeyWhisperMessage::getIdentityKey() const
{
    return identityKey;
}

ulong PreKeyWhisperMessage::getRegistrationId() const
{
    return registrationId;
}

ulong PreKeyWhisperMessage::getPreKeyId() const
{
    return preKeyId;
}

ulong PreKeyWhisperMessage::getSignedPreKeyId() const
{
    return signedPreKeyId;
}

DjbECPublicKey PreKeyWhisperMessage::getBaseKey() const
{
    return baseKey;
}

QSharedPointer<WhisperMessage> PreKeyWhisperMessage::getWhisperMessage()
{
    return message;
}

QByteArray PreKeyWhisperMessage::serialize() const
{
    return serialized;
}

int PreKeyWhisperMessage::getType() const
{
    return CiphertextMessage::PREKEY_TYPE;
}
