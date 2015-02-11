#include "hkdf.h"
#include <QtMath>
#include <QMessageAuthenticationCode>
#include <QDebug>

const float HKDF::HASH_OUTPUT_SIZE = 32;

HKDF::HKDF(int messageVersion)
{
    iterationStartOffset = 0;
    if (messageVersion == 2) {
        iterationStartOffset = 0;
    }
    else if (messageVersion == 3) {
        iterationStartOffset = 1;
    }
    else {
        // TODO exception
    }
}

int HKDF::getIterationStartOffset() const
{
    return iterationStartOffset;
}

QByteArray HKDF::expand(const QByteArray &prk, const QByteArray &info, int outputSize) const
{
    int iterations = qCeil((float)outputSize / HKDF::HASH_OUTPUT_SIZE);
    QByteArray mixin;
    QByteArray results;
    int remainingBytes = outputSize;

    for (int i = iterationStartOffset; i < (iterations + iterationStartOffset); i++) {

        QByteArray message;
        message.append(mixin);
        if (!info.isEmpty()) {
            message.append(info);
        }

        message.append(QByteArray(1, (char)(i % 256)));

        QByteArray stepResult = QMessageAuthenticationCode::hash(message, prk, QCryptographicHash::Sha256);
        int stepSize = qMin(remainingBytes, stepResult.size());
        results.append(stepResult.mid(0, stepSize));
        mixin = stepResult;
        remainingBytes -= stepSize;
    }
    return results;
}

QByteArray HKDF::extract(const QByteArray &salt, const QByteArray &inputKeyMaterial) const
{
    return QMessageAuthenticationCode::hash(inputKeyMaterial, salt, QCryptographicHash::Sha256);
}

QByteArray HKDF::deriveSecrets(const QByteArray &inputKeyMaterial, const QByteArray &info, int outputLength, const QByteArray &saltFirst) const
{
    QByteArray salt = saltFirst;
    if (salt.isEmpty()) {
        salt = QByteArray(HKDF::HASH_OUTPUT_SIZE, '\0');
    }
    QByteArray prk = extract(salt, inputKeyMaterial);
    return expand(prk, info, outputLength);
}
