#ifndef DJBEC_H
#define DJBEC_H

#include <QByteArray>

class DjbECPublicKey
{
public:
    DjbECPublicKey();
    DjbECPublicKey(const DjbECPublicKey &publicKey);
    DjbECPublicKey(const QByteArray &publicKey);
    QByteArray serialize() const;
    int getType() const;
    QByteArray getPublicKey() const;
    bool operator <(const DjbECPublicKey &otherKey);
    bool operator ==(const DjbECPublicKey &otherKey);

private:
    QByteArray publicKey;

};

class DjbECPrivateKey
{
public:
    DjbECPrivateKey();
    DjbECPrivateKey(const DjbECPrivateKey &privateKey);
    DjbECPrivateKey(const QByteArray &privateKey);
    QByteArray serialize() const;
    int getType() const;
    QByteArray getPrivateKey() const;
    bool operator <(const DjbECPrivateKey &otherKey);
    bool operator ==(const DjbECPrivateKey &otherKey);

private:
    QByteArray privateKey;

};

#endif // DJBEC_H
