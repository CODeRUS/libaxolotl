#include "senderkeymessage.h"

#include "../util/byteutil.h"
#include "../legacymessageexception.h"
#include "../invalidmessageexception.h"
#include "WhisperTextProtocol.pb.h"
#include "../ecc/curve.h"
#include "../invalidkeyexception.h"

#include <QDebug>

SenderKeyMessage::SenderKeyMessage(const QByteArray &serialized)
{
    QList<QByteArray> messageParts = ByteUtil::split(serialized, 1, serialized.size() - 1 - SIGNATURE_LENGTH, SIGNATURE_LENGTH);
    quint8     version             = messageParts[0][0];
    QByteArray message             = messageParts[1];
    //QByteArray signature           = messageParts[2];

    if (ByteUtil::highBitsToInt(version) < 3) {
        throw LegacyMessageException("Legacy message: " + ByteUtil::highBitsToInt(version));
    }

    if (ByteUtil::highBitsToInt(version) > CURRENT_VERSION) {
        throw InvalidMessageException("Unknown version: " + ByteUtil::highBitsToInt(version));
    }

    textsecure::SenderKeyMessage senderKeyMessage;
    senderKeyMessage.ParseFromArray(message.constData(), message.size());

    if (!senderKeyMessage.has_id() ||
        !senderKeyMessage.has_iteration() ||
        !senderKeyMessage.has_ciphertext())
    {
        qDebug() << "has_id" << senderKeyMessage.has_id();
        qDebug() << "has_iteration" << senderKeyMessage.has_iteration();
        qDebug() << "has_ciphertext" << senderKeyMessage.has_ciphertext();
        throw InvalidMessageException("Incomplete message.");
    }

    this->serialized     = serialized;
    this->messageVersion = ByteUtil::highBitsToInt(version);
    this->keyId          = senderKeyMessage.id();
    this->iteration      = senderKeyMessage.iteration();
    ::std::string senderKeyMessageCiphertext = senderKeyMessage.ciphertext();
    this->ciphertext     = QByteArray(senderKeyMessageCiphertext.data(), senderKeyMessageCiphertext.length());
}

SenderKeyMessage::SenderKeyMessage(ulong keyId, int iteration, const QByteArray &ciphertext, const DjbECPrivateKey &signatureKey)
{
    textsecure::SenderKeyMessage senderKeyMessage;
    senderKeyMessage.set_id(keyId);
    senderKeyMessage.set_iteration(iteration);
    senderKeyMessage.set_ciphertext(ciphertext.constData());
    ::std::string serializedMessage = senderKeyMessage.SerializeAsString();
    QByteArray message = QByteArray(serializedMessage.data(), serializedMessage.length());
    message.prepend(ByteUtil::intsToByteHighAndLow(CURRENT_VERSION, CURRENT_VERSION));
    message.append(getSignature(signatureKey, message));

    this->serialized       = message;
    this->messageVersion   = CURRENT_VERSION;
    this->keyId            = keyId;
    this->iteration        = iteration;
    this->ciphertext       = ciphertext;
}

void SenderKeyMessage::verifySignature(const DjbECPublicKey &signatureKey)
{
    try {
      QList<QByteArray> parts = ByteUtil::split(serialized, serialized.size() - SIGNATURE_LENGTH, SIGNATURE_LENGTH);

      if (!Curve::verifySignature(signatureKey, parts[0], parts[1])) {
          throw InvalidMessageException("Invalid signature!");
      }

    } catch (const InvalidKeyException &e) {
        throw InvalidMessageException(__PRETTY_FUNCTION__, QList<WhisperException>() << e);
    }
}

ulong SenderKeyMessage::getKeyId() const
{
    return keyId;
}

int SenderKeyMessage::getIteration() const
{
    return iteration;
}

QByteArray SenderKeyMessage::getCipherText() const
{
    return ciphertext;
}

QByteArray SenderKeyMessage::serialize() const
{
    return serialized;
}

int SenderKeyMessage::getType() const
{
    return CiphertextMessage::SENDERKEY_TYPE;
}

QByteArray SenderKeyMessage::getSignature(const DjbECPrivateKey &signatureKey, const QByteArray &serialized)
{
    return Curve::calculateSignature(signatureKey, serialized);
}
