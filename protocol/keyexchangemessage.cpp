#include "keyexchangemessage.h"
#include "ciphertextmessage.h"
#include "WhisperTextProtocol.pb.h"
#include "../util/byteutil.h"
#include "../ecc/curve.h"

#include "../legacymessageexception.h"
#include "../invalidversionexception.h"
#include "../invalidmessageexception.h"

KeyExchangeMessage::KeyExchangeMessage()
{

}

KeyExchangeMessage::KeyExchangeMessage(int messageVersion, int sequence, int flags, const DjbECPublicKey &baseKey, const QByteArray &baseKeySignature, const DjbECPublicKey &ratchetKey, const IdentityKey &identityKey)
{
    this->supportedVersion = CiphertextMessage::CURRENT_VERSION;
    this->version          = messageVersion;
    this->sequence         = sequence;
    this->flags            = flags;
    this->baseKey          = baseKey;
    this->baseKeySignature = baseKeySignature;
    this->ratchetKey       = ratchetKey;
    this->identityKey      = identityKey;

    textsecure::KeyExchangeMessage message;
    message.set_id((sequence << 5) | flags);
    message.set_basekey(baseKey.serialize().constData());
    message.set_ratchetkey(ratchetKey.serialize().constData());
    message.set_identitykey(identityKey.serialize().constData());

    if (messageVersion >= 3) {
        message.set_basekeysignature(baseKeySignature.constData());
    }

    ::std::string serializedMessage = message.SerializeAsString();
    this->serialized = QByteArray(serializedMessage.data(), serializedMessage.length());
    this->serialized.prepend(ByteUtil::intsToByteHighAndLow(this->version, this->supportedVersion));
}

KeyExchangeMessage::KeyExchangeMessage(const QByteArray &serialized)
{
    QList<QByteArray> parts = ByteUtil::split(serialized, 1, serialized.size() - 1);
    this->version           = ByteUtil::highBitsToInt(parts[0][0]);
    this->supportedVersion  = ByteUtil::lowBitsToInt(parts[0][0]);

    if (this->version <= CiphertextMessage::UNSUPPORTED_VERSION) {
        throw LegacyMessageException(QString("Unsupported legacy version: %1").arg(this->version));
    }

    if (this->version > CiphertextMessage::CURRENT_VERSION) {
        throw InvalidVersionException(QString("Unknown version: %1").arg(this->version));
    }

    textsecure::KeyExchangeMessage message;
    message.ParseFromArray(parts[1].constData(), parts[1].size());

    if (!message.has_id()          || !message.has_basekey()     ||
        !message.has_ratchetkey()  || !message.has_identitykey() ||
        (this->version >=3 && !message.has_basekeysignature()))
    {
        throw InvalidMessageException("Some required fields missing!");
    }

    this->sequence         = message.id() >> 5;
    this->flags            = message.id() & 0x1f;
    this->serialized       = serialized;
    ::std::string messagebasekey = message.basekey();
    this->baseKey          = Curve::decodePoint(QByteArray(messagebasekey.data(), messagebasekey.length()), 0);
    ::std::string messagebasekeysignature = message.basekeysignature();
    this->baseKeySignature = QByteArray(messagebasekeysignature.data(), messagebasekeysignature.length());
    ::std::string messageratchetkey = message.ratchetkey();
    this->ratchetKey       = Curve::decodePoint(QByteArray(messageratchetkey.data(), messageratchetkey.length()), 0);
    ::std::string messageidentitykey = message.identitykey();
    this->identityKey      = IdentityKey(QByteArray(messageidentitykey.data(), messageidentitykey.length()), 0);
}

int KeyExchangeMessage::getVersion() const
{
    return version;
}

DjbECPublicKey KeyExchangeMessage::getBaseKey() const
{
    return baseKey;
}

QByteArray KeyExchangeMessage::getBaseKeySignature() const
{
    return baseKeySignature;
}

DjbECPublicKey KeyExchangeMessage::getRatchetKey() const
{
    return ratchetKey;
}

IdentityKey KeyExchangeMessage::getIdentityKey() const
{
    return identityKey;
}

bool KeyExchangeMessage::hasIdentityKey() const
{
    return true;
}

int KeyExchangeMessage::getMaxVersion() const
{
    return supportedVersion;
}

bool KeyExchangeMessage::isResponse() const
{
    return (flags & RESPONSE_FLAG) != 0;
}

bool KeyExchangeMessage::isInitiate() const
{
    return (flags & INITIATE_FLAG) != 0;
}

bool KeyExchangeMessage::isResponseForSimultaneousInitiate() const
{
    return (flags & SIMULTAENOUS_INITIATE_FLAG) != 0;
}

int KeyExchangeMessage::getFlags() const
{
    return flags;
}

int KeyExchangeMessage::getSequence() const
{
    return sequence;
}

QByteArray KeyExchangeMessage::serialize() const
{
    return serialized;
}
