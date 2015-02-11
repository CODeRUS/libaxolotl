#include "senderkeydistributionmessage.h"
#include "WhisperTextProtocol.pb.h"
#include "../util/byteutil.h"

SenderKeyDistributionMessage::SenderKeyDistributionMessage(int id, int iteration, const QByteArray &chainKey, const DjbECPublicKey &signatureKey)
{
    //qint8 version = ByteUtil::intsToByteHighAndLow(CURRENT_VERSION, CURRENT_VERSION);

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
