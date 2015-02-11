#include "whispermessage.h"
#include "../invalidkeyexception.h"
#include "../invalidmessageexception.h"
#include "../legacymessageexception.h"
#include "WhisperTextProtocol.pb.h"
#include "../ecc/curve.h"

#include <QMessageAuthenticationCode>

#include <QDebug>

WhisperMessage::WhisperMessage()
{

}

WhisperMessage::WhisperMessage(const QByteArray &serialized)
{
    try {
        //QList<QByteArray> messageParts = ByteUtil::split(serialized, 1, serialized.size() - 1 - MAC_LENGTH, MAC_LENGTH);
        qint8     version      = serialized[0];
        QByteArray   message   = serialized.mid(1, serialized.size() - MAC_LENGTH - 1);
        QByteArray   mac       = serialized.right(MAC_LENGTH);
        //qDebug() << "serialized size:" << serialized.size() << "message size:" << message.size();

        if (ByteUtil::highBitsToInt(version) <= CiphertextMessage::UNSUPPORTED_VERSION) {
            throw LegacyMessageException("Legacy message: " + ByteUtil::highBitsToInt(version));
        }

        if (ByteUtil::highBitsToInt(version) > CURRENT_VERSION) {
            throw InvalidMessageException("Unknown version: " + ByteUtil::highBitsToInt(version));
        }

        textsecure::WhisperMessage whisperMessage;
        whisperMessage.ParseFromArray(message.constData(), message.size());

        if (!whisperMessage.has_ciphertext() ||
            !whisperMessage.has_counter() ||
            !whisperMessage.has_ratchetkey())
        {
            qDebug() << "has_ciphertext" << whisperMessage.has_ciphertext();
            qDebug() << "has_counter" << whisperMessage.has_counter();
            qDebug() << "has_ratchetkey" << whisperMessage.has_ratchetkey();
            throw InvalidMessageException("Incomplete message.");
        }

        this->serialized       = serialized;
        ::std::string whisperratchetkey = whisperMessage.ratchetkey();
        this->senderRatchetKey = Curve::decodePoint(QByteArray(whisperratchetkey.data(), whisperratchetkey.length()), 0);
        this->messageVersion   = ByteUtil::highBitsToInt(version);
        this->counter          = whisperMessage.counter();
        this->previousCounter  = whisperMessage.previouscounter();
        ::std::string whisperciphertext = whisperMessage.ciphertext();
        this->ciphertext       = QByteArray(whisperciphertext.data(), whisperciphertext.length());
    } catch (const InvalidKeyException &e) {
        throw InvalidMessageException(__PRETTY_FUNCTION__, QList<WhisperException>() << e);
    }
}

WhisperMessage::WhisperMessage(int messageVersion, const QByteArray &macKey, const DjbECPublicKey &senderRatchetKey, uint counter, uint previousCounter, const QByteArray &ciphertext, const IdentityKey &senderIdentityKey, const IdentityKey &receiverIdentityKey)
{
    textsecure::WhisperMessage whisperMessage;
    QByteArray ratchetKey = senderRatchetKey.serialize();
    whisperMessage.set_ratchetkey(ratchetKey.constData(), ratchetKey.size());
    whisperMessage.set_counter(counter);
    whisperMessage.set_previouscounter(previousCounter);
    whisperMessage.set_ciphertext(ciphertext.constData() ,ciphertext.size());
    ::std::string serializedMessage = whisperMessage.SerializeAsString();
    QByteArray message = QByteArray(serializedMessage.data(), serializedMessage.length());
    message.prepend(ByteUtil::intsToByteHighAndLow(messageVersion, CURRENT_VERSION));
    QByteArray mac     = getMac(messageVersion, senderIdentityKey, receiverIdentityKey, macKey, message);

    this->serialized       = message;
    this->serialized.append(mac);
    this->senderRatchetKey = senderRatchetKey;
    this->counter          = counter;
    this->previousCounter  = previousCounter;
    this->ciphertext       = ciphertext;
    this->messageVersion   = messageVersion;
}

DjbECPublicKey WhisperMessage::getSenderRatchetKey() const
{
    return senderRatchetKey;
}

int WhisperMessage::getMessageVersion() const
{
    return messageVersion;
}

uint WhisperMessage::getCounter() const
{
    return counter;
}

QByteArray WhisperMessage::getBody() const
{
    return ciphertext;
}

QByteArray WhisperMessage::serialize() const
{
    return serialized;
}

int WhisperMessage::getType() const
{
    return CiphertextMessage::WHISPER_TYPE;
}

QByteArray WhisperMessage::getMac(int messageVersion, const IdentityKey &senderIdentityKey, const IdentityKey &receiverIdentityKey, const QByteArray &macKey, QByteArray &serialized) const
{
    QMessageAuthenticationCode hmac(QCryptographicHash::Sha256, macKey);

    if (messageVersion >= 3) {
        hmac.addData(senderIdentityKey.getPublicKey().serialize());
        hmac.addData(receiverIdentityKey.getPublicKey().serialize());
    }

    hmac.addData(serialized);
    return ByteUtil::trim(hmac.result(), MAC_LENGTH);
}

void WhisperMessage::verifyMac(int messageVersion, const IdentityKey &senderIdentityKey, const IdentityKey &receiverIdentityKey, const QByteArray &macKey) const
{
    QList<QByteArray> parts = ByteUtil::split(serialized, serialized.size() - MAC_LENGTH, MAC_LENGTH);
    QByteArray ourMac = getMac(messageVersion, senderIdentityKey, receiverIdentityKey, macKey, parts[0]);
    QByteArray theirMac = parts[1];

    if (ourMac != theirMac) {
       throw InvalidMessageException("Bad Mac!");
    }
}
