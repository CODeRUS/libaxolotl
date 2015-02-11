#ifndef SENDERMESSAGEKEY_H
#define SENDERMESSAGEKEY_H

#include <QByteArray>

class SenderMessageKey
{
public:
    SenderMessageKey();
    SenderMessageKey(int iteration, const QByteArray &seed);

    int getIteration() const;
    QByteArray getIv() const;
    QByteArray getCipherKey() const;
    QByteArray getSeed() const;

private:
    int        iteration;
    QByteArray iv;
    QByteArray cipherKey;
    QByteArray seed;
};

#endif // SENDERMESSAGEKEY_H
