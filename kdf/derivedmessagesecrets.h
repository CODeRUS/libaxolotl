#ifndef DERIVEDMESSAGESECRETS_H
#define DERIVEDMESSAGESECRETS_H

#include <QByteArray>

class DerivedMessageSecrets
{
public:
    DerivedMessageSecrets(const QByteArray &okm);
    static const int SIZE;
    static const int CIPHER_KEY_LENGTH;
    static const int MAC_KEY_LENGTH;
    static const int IV_LENGTH;

    QByteArray getCipherKey() const;
    QByteArray getMacKey() const;
    QByteArray getIv() const;

private:
    QByteArray cipherKey;
    QByteArray macKey;
    QByteArray iv;

};

#endif // DERIVEDMESSAGESECRETS_H
