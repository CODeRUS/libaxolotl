#include "senderkeydistributionmessage.h"
#include "WhisperTextProtocol.pb.h"
#include "util/byteutil.h"
#include "ecc/curve.h"
#include "legacymessageexception.h"
#include "invalidmessageexception.h"

#include <QDebug>

SenderKeyDistributionMessage::SenderKeyDistributionMessage(int id, int iteration, const QByteArray &chainKey, const DjbECPublicKey &signatureKey)
{
    qint8 version = ByteUtil::intsToByteHighAndLow(CURRENT_VERSION, CURRENT_VERSION);

    this->id           = id;
    this->iteration    = iteration;
    this->chainKey     = chainKey;
    this->signatureKey = signatureKey;
    textsecure::SenderKeyDistributionMessage distributionMessage;
    distributionMessage.set_id(id);
    distributionMessage.set_iteration(iteration);
    distributionMessage.set_chainkey(chainKey.constData());
    distributionMessage.set_signingkey(signatureKey.serialize().constData());
    ::std::string serializedMessage = distributionMessage.SerializeAsString();
    this->serialized = QByteArray(serializedMessage.data(), serializedMessage.length());
    this->serialized.prepend(version);
}

SenderKeyDistributionMessage::SenderKeyDistributionMessage(const QByteArray &serialized)
{
    qint8      version = serialized[0];
    QByteArray message = serialized.mid(1);

    if (ByteUtil::highBitsToInt(version) < CiphertextMessage::CURRENT_VERSION) {
        throw LegacyMessageException("Legacy message: " + ByteUtil::highBitsToInt(version));
    }

    if (ByteUtil::highBitsToInt(version) > CURRENT_VERSION) {
        throw InvalidMessageException("Unknown version: " + ByteUtil::highBitsToInt(version));
    }

    textsecure::SenderKeyDistributionMessage senderKeyDistributionMessage;
    senderKeyDistributionMessage.ParseFromArray(message.constData(), message.size());

    if (!senderKeyDistributionMessage.has_id() ||
        !senderKeyDistributionMessage.has_iteration() ||
        !senderKeyDistributionMessage.has_chainkey() ||
        !senderKeyDistributionMessage.has_signingkey())
    {
        qDebug() << "has_id" << senderKeyDistributionMessage.has_id();
        qDebug() << "has_iteration" << senderKeyDistributionMessage.has_iteration();
        qDebug() << "has_chainkey" << senderKeyDistributionMessage.has_chainkey();
        qDebug() << "has_signingkey" << senderKeyDistributionMessage.has_signingkey();
        throw InvalidMessageException("Incomplete message.");
    }

    this->serialized     = serialized;
    this->id             = senderKeyDistributionMessage.id();
    this->iteration      = senderKeyDistributionMessage.iteration();
    ::std::string chainKeyString = senderKeyDistributionMessage.chainkey();
    this->chainKey       = QByteArray(chainKeyString.data(), chainKeyString.length());
    ::std::string signatureKeyString = senderKeyDistributionMessage.signingkey();
    this->signatureKey   = Curve::decodePoint(QByteArray(signatureKeyString.data(), signatureKeyString.length()), 0);
}

QByteArray SenderKeyDistributionMessage::serialize() const
{
    return serialized;
}

int SenderKeyDistributionMessage::getType() const
{
    return CiphertextMessage::SENDERKEY_DISTRIBUTION_TYPE;
}

int SenderKeyDistributionMessage::getIteration() const
{
    return iteration;
}

QByteArray SenderKeyDistributionMessage::getChainKey() const
{
    return chainKey;
}

DjbECPublicKey SenderKeyDistributionMessage::getSignatureKey() const
{
    return signatureKey;
}

int SenderKeyDistributionMessage::getId() const
{
    return id;
}
