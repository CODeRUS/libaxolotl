#ifndef HKDF_H
#define HKDF_H

#include <QByteArray>

class HKDF
{
public:
    HKDF(int messageVersion = 2);
    static const float HASH_OUTPUT_SIZE;
    int getIterationStartOffset() const;
    QByteArray expand(const QByteArray &prk, const QByteArray &info, int outputSize) const;
    QByteArray extract(const QByteArray &salt, const QByteArray &inputKeyMaterial) const;
    QByteArray deriveSecrets(const QByteArray &inputKeyMaterial, const QByteArray &info, int outputLength, const QByteArray &saltFirst = QByteArray()) const;

private:
    int iterationStartOffset;

};

#endif // HKDF_H
