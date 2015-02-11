#ifndef MESSAGEKEYS_H
#define MESSAGEKEYS_H

#include <QByteArray>

class MessageKeys
{
public:
    MessageKeys();
    MessageKeys(const QByteArray &cipherKey, const QByteArray &macKey, const QByteArray &iv, uint counter);

    QByteArray getCipherKey() const;
    QByteArray getMacKey() const;
    QByteArray getIv() const;
    uint getCounter() const;

private:
    QByteArray cipherKey;
    QByteArray macKey;
    QByteArray iv;
    uint counter;

};

#endif // MESSAGEKEYS_H
