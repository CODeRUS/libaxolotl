#ifndef DERIVEDROOTSECRETS_H
#define DERIVEDROOTSECRETS_H

#include <QByteArray>

class DerivedRootSecrets
{
public:
    DerivedRootSecrets(const QByteArray &okm);
    static const int SIZE;

    QByteArray getRootKey() const;
    QByteArray getChainKey() const;

private:
    QByteArray rootKey;
    QByteArray chainKey;

};

#endif // DERIVEDROOTSECRETS_H
