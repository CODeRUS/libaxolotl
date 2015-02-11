#ifndef WHISPERMESSAGE_H
#define WHISPERMESSAGE_H

#include "ciphertextmessage.h"
#include "../ecc/djbec.h"
#include "../identitykey.h"
#include "../util/byteutil.h"

#include <QByteArray>

class WhisperMessage : public CiphertextMessage
{
public:
    static const int MAC_LENGTH = 8;

    WhisperMessage();
    virtual ~WhisperMessage() {}
    WhisperMessage(const QByteArray &serialized);
    WhisperMessage(int messageVersion, const QByteArray &macKey, const DjbECPublicKey &senderRatchetKey,
                   uint counter, uint previousCounter, const QByteArray &ciphertext,
                   const IdentityKey &senderIdentityKey,
                   const IdentityKey &receiverIdentityKey);
    void verifyMac(int messageVersion, const IdentityKey &senderIdentityKey,
                   const IdentityKey &receiverIdentityKey, const QByteArray &macKey) const;

    DjbECPublicKey getSenderRatchetKey() const;
    int getMessageVersion() const;
    uint getCounter() const;
    QByteArray getBody() const;
    QByteArray serialize() const;
    int getType() const;

    static bool isLegacy(const QByteArray &message) {
        return !message.isEmpty() && message.length() >= 1 &&
            ByteUtil::highBitsToInt(message[0]) <= CiphertextMessage::UNSUPPORTED_VERSION;
    }

private:
    QByteArray getMac(int messageVersion,
                      const IdentityKey &senderIdentityKey,
                      const IdentityKey &receiverIdentityKey,
                      const QByteArray &macKey, QByteArray &serialized) const;

    int         messageVersion;
    DjbECPublicKey senderRatchetKey;
    uint        counter;
    uint        previousCounter;
    QByteArray  ciphertext;
    QByteArray  serialized;
};

#endif // WHISPERMESSAGE_H
