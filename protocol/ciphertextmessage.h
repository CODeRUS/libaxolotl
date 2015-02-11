#ifndef CIPHERTEXTMESSAGE_H
#define CIPHERTEXTMESSAGE_H

#include <QByteArray>

class CiphertextMessage
{
public:
    static const int UNSUPPORTED_VERSION         = 1;
    static const int CURRENT_VERSION             = 3;

    static const int WHISPER_TYPE                = 2;
    static const int PREKEY_TYPE                 = 3;
    static const int SENDERKEY_TYPE              = 4;
    static const int SENDERKEY_DISTRIBUTION_TYPE = 5;

    // This should be the worst case (worse than V2).  So not always accurate, but good enough for padding.
    static const int ENCRYPTED_MESSAGE_OVERHEAD = 53;

    virtual QByteArray serialize() const = 0;
    virtual int getType() const = 0;
    virtual ~CiphertextMessage() {}
};

#endif // CIPHERTEXTMESSAGE_H
